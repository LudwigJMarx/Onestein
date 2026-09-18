//! The five records, and the rule that decides when a message may be
//! delivered.
//!
//! Spec: `spec/50-sync.md` §5, §7.

use onestein_crypto::HASH_LEN;
use onestein_record::{Reader, encode};

use crate::{Error, MessageId, SYNC_VERSION, SignedMessage, decode_message};

/// Type byte 0.
pub const TYPE_ACK: u8 = 0;
/// Type byte 1.
pub const TYPE_MESSAGE: u8 = 1;
/// Type byte 2.
pub const TYPE_OFFER: u8 = 2;
/// Type byte 3.
pub const TYPE_REQUEST: u8 = 3;
/// Type byte 4.
pub const TYPE_UNAVAILABLE: u8 = 4;

/// One record of a sync session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncRecord<'a> {
    /// Messages the sender has seen.
    Ack(Vec<MessageId>),
    /// A message.
    Message(SignedMessage<'a>),
    /// Messages the sender holds and is sharing.
    Offer(Vec<MessageId>),
    /// Messages the sender wants.
    Request(Vec<MessageId>),
    /// Messages the sender cannot supply: deleted, never held, or not shared.
    ///
    /// Not a promise. It closes a wait, not a door.
    Unavailable(Vec<MessageId>),
    /// A type this version does not know, handed over so the caller can
    /// ignore it.
    Unknown {
        /// The type byte on the wire.
        record_type: u8,
    },
}

/// Writes one record.
///
/// # Errors
///
/// [`Error::Malformed`] for an empty identifier list, which the record types
/// define as "one or more".
pub fn encode_record(record: &SyncRecord) -> Result<Vec<u8>, Error> {
    let (record_type, payload) = match record {
        SyncRecord::Ack(ids) => (TYPE_ACK, identifiers(ids)?),
        SyncRecord::Offer(ids) => (TYPE_OFFER, identifiers(ids)?),
        SyncRecord::Request(ids) => (TYPE_REQUEST, identifiers(ids)?),
        SyncRecord::Unavailable(ids) => (TYPE_UNAVAILABLE, identifiers(ids)?),
        SyncRecord::Message(signed) => (TYPE_MESSAGE, signed.message.encode(&signed.signature)?),
        // Nothing here knows what an unknown record meant, so nothing here
        // can write one back.
        SyncRecord::Unknown { .. } => return Err(Error::Malformed),
    };
    encode(SYNC_VERSION, record_type, &payload).map_err(|_| Error::Malformed)
}

/// Flattens an identifier list, refusing an empty one: every record type that
/// carries identifiers says "one or more", and an empty list is a record that
/// costs a round trip and says nothing.
fn identifiers(ids: &[MessageId]) -> Result<Vec<u8>, Error> {
    if ids.is_empty() {
        return Err(Error::Malformed);
    }
    let mut payload = Vec::with_capacity(ids.len().saturating_mul(HASH_LEN));
    for id in ids {
        payload.extend_from_slice(id.as_bytes());
    }
    Ok(payload)
}

fn parse_identifiers(payload: &[u8]) -> Result<Vec<MessageId>, Error> {
    if payload.is_empty() || payload.len() % HASH_LEN != 0 {
        return Err(Error::Malformed);
    }
    payload
        .chunks(HASH_LEN)
        .map(|chunk| {
            <[u8; HASH_LEN]>::try_from(chunk)
                .map(MessageId::from_bytes)
                .map_err(|_| Error::Malformed)
        })
        .collect()
}

/// Reads the records of one message.
///
/// # Errors
///
/// [`Error::Malformed`] for framing or for a payload that is not what its
/// type requires.
pub fn decode_records(input: &[u8]) -> Result<Vec<SyncRecord<'_>>, Error> {
    let mut out = Vec::new();
    for framed in Reader::new(input, SYNC_VERSION) {
        let record = framed.map_err(|_| Error::Malformed)?;
        let payload = record.payload;
        out.push(match record.record_type {
            TYPE_ACK => SyncRecord::Ack(parse_identifiers(payload)?),
            TYPE_MESSAGE => SyncRecord::Message(decode_message(payload)?),
            TYPE_OFFER => SyncRecord::Offer(parse_identifiers(payload)?),
            TYPE_REQUEST => SyncRecord::Request(parse_identifiers(payload)?),
            TYPE_UNAVAILABLE => SyncRecord::Unavailable(parse_identifiers(payload)?),
            record_type => SyncRecord::Unknown { record_type },
        });
    }
    Ok(out)
}

/// Whether a message may be delivered to its client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deliverability {
    /// Every dependency is either delivered or inside the horizon.
    Ready {
        /// True when some dependency was satisfied by the horizon rather than
        /// by having been received, here or further back.
        ///
        /// The client decides what that is worth. A conversation shows the
        /// message; a ledger refuses it. This layer reports and does not
        /// decide.
        ancestry_incomplete: bool,
    },
    /// Something is missing and may still arrive.
    Waiting,
}

/// Applies the delivery rule.
///
/// The two closures are how the caller keeps the state: one says whether a
/// dependency has been delivered and whether its own ancestry was complete,
/// the other whether it lies inside this member's horizon.
pub fn deliverability(
    dependencies: &[MessageId],
    delivered: impl Fn(&MessageId) -> Option<bool>,
    in_horizon: impl Fn(&MessageId) -> bool,
) -> Deliverability {
    let mut ancestry_incomplete = false;
    for dependency in dependencies {
        match delivered(dependency) {
            // Incompleteness travels forward: a message resting on one that
            // was itself delivered with a gap behind it is no better founded.
            Some(incomplete) => ancestry_incomplete |= incomplete,
            None if in_horizon(dependency) => ancestry_incomplete = true,
            None => return Deliverability::Waiting,
        }
    }
    Deliverability::Ready {
        ancestry_incomplete,
    }
}
