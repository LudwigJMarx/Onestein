//! Conformance vectors for BSP group and message identifiers.
//!
//! Expected values from `scripts/vektoren-bsp-hash.py` (CPython hashlib).
//! The example inputs are arbitrary but fixed: changing them changes the
//! vectors and with them the evidence.
//!
//! Spec: BSP 2.3, 2.4.

use onestein_sync::{
    Error, GroupId, MAX_GROUP_DESCRIPTOR_LEN, MAX_MESSAGE_BODY_LEN, MessageId, body_hash,
};

const CLIENT_ID: &str = "com.example.test";
const CLIENT_MAJOR: u32 = 1;
const GROUP_DESCRIPTOR: [u8; 2] = [0x01, 0x02];
const MESSAGE_BODY: &[u8] = b"hello";
const TIMESTAMP_MS: u64 = 1_600_000_000_000;

const GROUP_ID: [u8; 32] = [
    0x64, 0x0f, 0x0a, 0x8e, 0x89, 0x10, 0xcf, 0x68, 0x6d, 0x78, 0x09, 0x3e, 0x1a, 0xf4, 0x05, 0x7a,
    0x48, 0xaa, 0x23, 0xfe, 0x9c, 0x05, 0xd5, 0xc6, 0xf5, 0xc1, 0xe9, 0x85, 0x22, 0xa6, 0xdf, 0x83,
];
const BODY_HASH: [u8; 32] = [
    0xb0, 0xe6, 0x76, 0xa9, 0x6a, 0x73, 0x17, 0x0b, 0x25, 0x67, 0xb7, 0x3f, 0x36, 0x90, 0x86, 0x12,
    0x4a, 0x36, 0x7b, 0x5a, 0x22, 0x35, 0xfd, 0xb9, 0x92, 0xad, 0x61, 0x02, 0x3b, 0x75, 0x8f, 0x2c,
];
const MESSAGE_ID: [u8; 32] = [
    0x10, 0x1e, 0x33, 0x91, 0x7c, 0xab, 0xcb, 0x6d, 0x2d, 0x03, 0x11, 0xc6, 0x17, 0xab, 0xb6, 0xd2,
    0xb6, 0x9a, 0x67, 0xe5, 0x39, 0x21, 0x74, 0xf3, 0x61, 0xb2, 0x11, 0x55, 0x72, 0x05, 0x7f, 0xe8,
];

fn group() -> GroupId {
    GroupId::derive(CLIENT_ID, CLIENT_MAJOR, &GROUP_DESCRIPTOR).expect("the example group derives")
}

// "group_id = HASH("org.briarproject.bramble/GROUP_ID",
// int_8(group_format_version), client_id, int_32(client_major_version),
// group_descriptor)"
#[test]
fn a_group_identifier_matches_the_specification() {
    assert_eq!(group().as_bytes(), &GROUP_ID);
}

// "The client identifier and major version are included when calculating
// group identifiers, so different major versions of a given client use
// distinct groups".
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

// "body_hash = HASH("org.briarproject.bramble/MESSAGE_BLOCK",
// int_8(message_format_version), message_body)"
#[test]
fn a_body_hash_matches_the_specification() {
    assert_eq!(body_hash(MESSAGE_BODY), Ok(BODY_HASH));
}

// "message_id = HASH("org.briarproject.bramble/MESSAGE_ID",
// int_8(message_format_version), group_id, int_64(timestamp), body_hash)"
#[test]
fn a_message_identifier_matches_the_specification() {
    let id = MessageId::derive(&group(), TIMESTAMP_MS, MESSAGE_BODY)
        .expect("the example message derives");
    assert_eq!(id.as_bytes(), &MESSAGE_ID);
}

#[test]
fn the_timestamp_is_part_of_the_identifier() {
    let earlier = MessageId::derive(&group(), TIMESTAMP_MS - 1, MESSAGE_BODY);
    let later = MessageId::derive(&group(), TIMESTAMP_MS, MESSAGE_BODY);
    assert_ne!(earlier, later);
}

// "The maximum length of a group descriptor is 16 KiB."
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

// "The maximum length of a message body is 32 KiB."
#[test]
fn a_message_body_over_32_kib_is_refused() {
    let just_fits = vec![0u8; MAX_MESSAGE_BODY_LEN];
    assert!(MessageId::derive(&group(), TIMESTAMP_MS, &just_fits).is_ok());
    let one_too_many = vec![0u8; MAX_MESSAGE_BODY_LEN + 1];
    assert_eq!(
        MessageId::derive(&group(), TIMESTAMP_MS, &one_too_many),
        Err(Error::MessageBodyTooLong(MAX_MESSAGE_BODY_LEN + 1))
    );
    assert_eq!(
        body_hash(&one_too_many),
        Err(Error::MessageBodyTooLong(MAX_MESSAGE_BODY_LEN + 1))
    );
}
