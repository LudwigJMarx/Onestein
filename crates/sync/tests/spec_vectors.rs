//! Conformance vectors for group and message identifiers.
//!
//! Expected values from `scripts/vektoren.py` (CPython hashlib). The example
//! inputs are arbitrary but fixed: changing them changes the vectors and with
//! them the evidence.
//!
//! Spec: `spec/50-sync.md` §2.

use onestein_identity::IdentityId;
use onestein_sync::{
    Error, GroupId, MAX_GROUP_DESCRIPTOR_LEN, MAX_MESSAGE_BODY_LEN, MessageId, body_hash,
};

const ROOT_ED25519: [u8; 32] = [0x11; 32];
const ROOT_MLDSA: [u8; 1952] = [0x22; 1952];
const DEVICE_SIGNING: [u8; 32] = [0x33; 32];
const CLIENT_ID: &str = "com.example.test";
const CLIENT_MAJOR: u32 = 1;
const GROUP_DESCRIPTOR: [u8; 2] = [0x01, 0x02];
const MESSAGE_BODY: &[u8] = b"hello";
const TIMESTAMP_MS: u64 = 1_600_000_000_000;

const GROUP_ID: [u8; 32] = [
    0xb5, 0xc1, 0xa5, 0x2b, 0x3c, 0xb3, 0x95, 0xe6, 0x52, 0x51, 0x4c, 0x52, 0x95, 0x7b, 0x2b, 0x86,
    0xe5, 0x5d, 0x8f, 0x16, 0xc3, 0xbe, 0x57, 0x96, 0xb6, 0x99, 0x0b, 0xcb, 0x07, 0xd2, 0x72, 0x85,
];
const BODY_HASH: [u8; 32] = [
    0xf5, 0xeb, 0x62, 0xba, 0x2e, 0xe2, 0xea, 0x68, 0xcf, 0xc9, 0xe1, 0x34, 0xc2, 0x57, 0x22, 0x1b,
    0x56, 0xdc, 0x5f, 0xc6, 0x17, 0x76, 0x09, 0xdf, 0xfb, 0x4b, 0xdf, 0xc2, 0x4d, 0xcf, 0xae, 0xff,
];
const MESSAGE_ID: [u8; 32] = [
    0xfb, 0xe1, 0xb2, 0xe0, 0xf1, 0xcd, 0x9e, 0x59, 0x2d, 0x28, 0xf0, 0x0d, 0x6d, 0x63, 0x7f, 0xe7,
    0x8d, 0x47, 0x81, 0xe4, 0xf1, 0x52, 0xac, 0x3b, 0x81, 0x42, 0x7c, 0xa1, 0xcb, 0x0a, 0xa3, 0x7a,
];

fn group() -> GroupId {
    GroupId::derive(CLIENT_ID, CLIENT_MAJOR, &GROUP_DESCRIPTOR).expect("the example group derives")
}

fn author() -> IdentityId {
    IdentityId::derive(&ROOT_ED25519, &ROOT_MLDSA).expect("the example identity derives")
}

// "group_id = HASH("org.onestein.sync/GROUP_ID", int_8(sync_version),
// client_id, int_32(client_major_version), group_descriptor)"
#[test]
fn a_group_identifier_matches_the_specification() {
    assert_eq!(group().as_bytes(), &GROUP_ID);
}

// "a breaking change to a client puts it in different groups instead of
// putting it in the same group speaking differently"
#[test]
fn a_different_major_version_is_a_different_group() {
    let other = GroupId::derive(CLIENT_ID, CLIENT_MAJOR + 1, &GROUP_DESCRIPTOR);
    assert_ne!(Ok(group()), other);
}

#[test]
fn a_different_client_is_a_different_group() {
    let other = GroupId::derive("com.example.other", CLIENT_MAJOR, &GROUP_DESCRIPTOR);
    assert_ne!(Ok(group()), other);
}

// "body_hash = HASH("org.onestein.sync/MESSAGE_BLOCK", int_8(sync_version), body)"
#[test]
fn a_body_hash_matches_the_specification() {
    assert_eq!(body_hash(MESSAGE_BODY), Ok(BODY_HASH));
}

// "message_id = HASH("org.onestein.sync/MESSAGE_ID", int_8(sync_version),
// group_id, int_64(timestamp), author_identity_id, author_device_key,
// body_hash)"
#[test]
fn a_message_identifier_matches_the_specification() {
    let id = MessageId::derive(
        &group(),
        TIMESTAMP_MS,
        &author(),
        &DEVICE_SIGNING,
        MESSAGE_BODY,
    )
    .expect("the example message derives");
    assert_eq!(id.as_bytes(), &MESSAGE_ID);
}

// Authorship is part of the identifier, so the same words from two people are
// two messages. Without that, a third party could not tell them apart, and
// §3 makes a third party the point.
#[test]
fn the_author_is_part_of_the_identifier() {
    let other_author = IdentityId::derive(&[0x44; 32], &ROOT_MLDSA).expect("derives");
    let mine = MessageId::derive(
        &group(),
        TIMESTAMP_MS,
        &author(),
        &DEVICE_SIGNING,
        MESSAGE_BODY,
    );
    let theirs = MessageId::derive(
        &group(),
        TIMESTAMP_MS,
        &other_author,
        &DEVICE_SIGNING,
        MESSAGE_BODY,
    );
    assert_ne!(mine, theirs);
}

// Two devices of one identity writing the same words at the same moment are
// still two messages, because the device key is in the identifier.
#[test]
fn the_device_key_is_part_of_the_identifier() {
    let one = MessageId::derive(
        &group(),
        TIMESTAMP_MS,
        &author(),
        &DEVICE_SIGNING,
        MESSAGE_BODY,
    );
    let two = MessageId::derive(&group(), TIMESTAMP_MS, &author(), &[0x55; 32], MESSAGE_BODY);
    assert_ne!(one, two);
}

#[test]
fn the_timestamp_is_part_of_the_identifier() {
    let earlier = MessageId::derive(
        &group(),
        TIMESTAMP_MS - 1,
        &author(),
        &DEVICE_SIGNING,
        MESSAGE_BODY,
    );
    let later = MessageId::derive(
        &group(),
        TIMESTAMP_MS,
        &author(),
        &DEVICE_SIGNING,
        MESSAGE_BODY,
    );
    assert_ne!(earlier, later);
}

// "A group descriptor is at most 16 KiB, a body at most 32 KiB."
#[test]
fn a_group_descriptor_over_16_kib_is_refused() {
    let just_fits = vec![0u8; MAX_GROUP_DESCRIPTOR_LEN];
    assert!(GroupId::derive(CLIENT_ID, CLIENT_MAJOR, &just_fits).is_ok());
    let one_too_many = vec![0u8; MAX_GROUP_DESCRIPTOR_LEN + 1];
    assert_eq!(
        GroupId::derive(CLIENT_ID, CLIENT_MAJOR, &one_too_many),
        Err(Error::GroupDescriptorTooLong(MAX_GROUP_DESCRIPTOR_LEN + 1))
    );
}

#[test]
fn a_message_body_over_32_kib_is_refused() {
    let just_fits = vec![0u8; MAX_MESSAGE_BODY_LEN];
    assert!(
        MessageId::derive(
            &group(),
            TIMESTAMP_MS,
            &author(),
            &DEVICE_SIGNING,
            &just_fits
        )
        .is_ok()
    );
    let one_too_many = vec![0u8; MAX_MESSAGE_BODY_LEN + 1];
    assert_eq!(
        MessageId::derive(
            &group(),
            TIMESTAMP_MS,
            &author(),
            &DEVICE_SIGNING,
            &one_too_many
        ),
        Err(Error::MessageBodyTooLong(MAX_MESSAGE_BODY_LEN + 1))
    );
    assert_eq!(
        body_hash(&one_too_many),
        Err(Error::MessageBodyTooLong(MAX_MESSAGE_BODY_LEN + 1))
    );
}
