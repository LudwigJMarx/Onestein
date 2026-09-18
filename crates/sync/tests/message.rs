//! Messages and their signatures.
//!
//! Spec: `spec/50-sync.md` §2, §3, §7.

use ed25519_dalek::{Signer, SigningKey};
use onestein_identity::IdentityId;
use onestein_sync::{
    Error, GroupId, MAX_MESSAGE_BODY_LEN, MESSAGE_HEADER_LEN, Message, SIGNATURE_LEN,
    SignedMessage, decode_message,
};

const BODY: &[u8] = b"hello";

fn device() -> SigningKey {
    SigningKey::from_bytes(&[0x77; 32])
}

fn author() -> IdentityId {
    IdentityId::derive(&[0x11; 32], &[0x22; 1952]).expect("derives")
}

fn group() -> GroupId {
    GroupId::derive("com.example.test", 1, &[0x01, 0x02]).expect("derives")
}

fn message() -> Message<'static> {
    Message {
        group_id: group(),
        timestamp_ms: 1_600_000_000_000,
        author: author(),
        device_key: device().verifying_key().to_bytes(),
        body: BODY,
    }
}

fn signed() -> SignedMessage<'static> {
    let to_sign = message().to_sign().expect("signs");
    SignedMessage {
        message: message(),
        signature: device().sign(&to_sign).to_bytes(),
    }
}

// "payload = group_id (32) || int_64(timestamp) || author (32) ||
// device_key (32) || signature (64) || body", 168 bytes before the body.
#[test]
fn a_message_payload_has_the_layout_the_document_fixes() {
    assert_eq!(MESSAGE_HEADER_LEN, 168);
    let encoded = message().encode(&signed().signature).expect("encodes");
    assert_eq!(encoded.len(), MESSAGE_HEADER_LEN + BODY.len());

    let tail: Vec<u8> = encoded.iter().skip(MESSAGE_HEADER_LEN).copied().collect();
    assert_eq!(tail, BODY);
    let head: Vec<u8> = encoded.iter().take(32).copied().collect();
    assert_eq!(head, group().as_bytes().to_vec());
}

#[test]
fn a_message_round_trips_and_verifies() {
    let encoded = message().encode(&signed().signature).expect("encodes");
    let decoded = decode_message(&encoded).expect("decodes");
    assert_eq!(decoded, signed());
    assert_eq!(decoded.verify(), Ok(()));
}

// The signature covers the identifier, which covers every field. Changing any
// of them has to break it, or a message could be edited in flight and still
// look like its author's.
#[test]
fn changing_anything_breaks_the_signature() {
    let mut altered = signed();
    altered.message.body = b"goodbye";
    assert_eq!(altered.verify(), Err(Error::BadSignature));

    let mut altered = signed();
    altered.message.timestamp_ms += 1;
    assert_eq!(altered.verify(), Err(Error::BadSignature));

    let mut altered = signed();
    altered.message.author = IdentityId::derive(&[0x33; 32], &[0x44; 1952]).expect("derives");
    assert_eq!(altered.verify(), Err(Error::BadSignature));

    let mut altered = signed();
    if let Some(byte) = altered.signature.first_mut() {
        *byte ^= 1;
    }
    assert_eq!(altered.verify(), Err(Error::BadSignature));
}

// A signature by some other device does not become valid by naming a
// different key: the key in the message is the one that is checked.
#[test]
fn another_devices_signature_does_not_pass() {
    let stranger = SigningKey::from_bytes(&[0x88; 32]);
    let to_sign = message().to_sign().expect("signs");
    let forged = SignedMessage {
        message: message(),
        signature: stranger.sign(&to_sign).to_bytes(),
    };
    assert_eq!(forged.verify(), Err(Error::BadSignature));
}

#[test]
fn a_payload_shorter_than_a_header_is_refused() {
    assert_eq!(decode_message(&[0u8; 167]), Err(Error::Malformed));
    assert!(decode_message(&[0u8; MESSAGE_HEADER_LEN]).is_ok());
}

#[test]
fn a_body_over_the_limit_is_refused() {
    let long = vec![0u8; MAX_MESSAGE_BODY_LEN + 1];
    let mut over = message();
    over.body = &long;
    assert_eq!(
        over.encode(&[0u8; SIGNATURE_LEN]),
        Err(Error::MessageBodyTooLong(MAX_MESSAGE_BODY_LEN + 1))
    );

    let mut payload = vec![0u8; MESSAGE_HEADER_LEN];
    payload.extend_from_slice(&long);
    assert_eq!(decode_message(&payload), Err(Error::Malformed));
}
