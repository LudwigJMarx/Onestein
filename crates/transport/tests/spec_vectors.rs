//! Conformance vectors for transport key management.
//!
//! Expected values from `scripts/vektoren.py` (CPython hashlib). Root key and
//! stream number are fill patterns, fixed from here on.
//!
//! Spec: `spec/20-transport.md` §4, §5, §6.

use onestein_transport::{Error, MAX_ROTATIONS, MEDIA, PeriodKeys, RELAY, Role, TAG_LEN, TOR, tag};

const ROOT_KEY: [u8; 32] = [0x44; 32];
const STREAM_NUMBER: u64 = 7;
/// The agreed timestamp falls in period 700, so the initial keys are period 699.
const TIMESTAMP_MS: u64 = 700 * 90_000 * 1_000 + 1;

const A_TAG_KEY_INITIAL: [u8; 32] = [
    0x3f, 0xd4, 0xd2, 0x48, 0xfc, 0x89, 0x93, 0xfa, 0xba, 0x0a, 0x8f, 0x42, 0x4b, 0x47, 0x8f, 0x0d,
    0xe2, 0x5f, 0x9d, 0x6c, 0x70, 0xbd, 0x18, 0xe2, 0x04, 0xf9, 0x82, 0x1d, 0x0c, 0x1e, 0x4c, 0x5f,
];
const A_HEADER_KEY_INITIAL: [u8; 32] = [
    0x3e, 0x3a, 0xd2, 0x81, 0xfc, 0x95, 0x51, 0xe6, 0x2a, 0xac, 0x51, 0xb0, 0x2b, 0xf7, 0x5b, 0x59,
    0x94, 0x9c, 0xb3, 0xb4, 0x3b, 0x8a, 0xa6, 0x8b, 0x00, 0x6f, 0x33, 0xa4, 0x05, 0x50, 0x52, 0xe8,
];
const B_TAG_KEY_INITIAL: [u8; 32] = [
    0x01, 0x01, 0xbe, 0x3c, 0xb6, 0xd1, 0x22, 0x68, 0x2b, 0xc9, 0x0f, 0x2b, 0xe2, 0x80, 0xdc, 0xa2,
    0x8e, 0x0d, 0x13, 0x66, 0x90, 0xd6, 0xfc, 0x8e, 0xfa, 0x4b, 0xf6, 0xc7, 0x0b, 0xb3, 0x9a, 0x3e,
];
const B_HEADER_KEY_INITIAL: [u8; 32] = [
    0x7e, 0x67, 0x3f, 0xf0, 0x54, 0xcb, 0x43, 0x02, 0x30, 0x27, 0x92, 0xa5, 0x07, 0x00, 0x66, 0x29,
    0x3b, 0x12, 0x8e, 0x38, 0x7a, 0x3d, 0x1b, 0xdc, 0x4d, 0xac, 0xe5, 0x70, 0x5b, 0x3f, 0x52, 0x36,
];
const A_TAG_KEY_PERIOD_700: [u8; 32] = [
    0x21, 0xfc, 0xe7, 0x55, 0xd0, 0xf2, 0xd0, 0x5e, 0x9c, 0x2c, 0x2d, 0x53, 0x6d, 0x39, 0xa2, 0x71,
    0x43, 0xaa, 0x31, 0x3f, 0x34, 0x3e, 0xf4, 0xe3, 0xaf, 0x70, 0xad, 0x84, 0x7a, 0x2e, 0xf6, 0x84,
];
const A_TAG_KEY_PERIOD_701: [u8; 32] = [
    0xbf, 0x3a, 0xce, 0xe2, 0x83, 0xea, 0x11, 0xaa, 0x5c, 0xcc, 0x8f, 0xac, 0x82, 0x17, 0x73, 0x8e,
    0xe2, 0x42, 0x79, 0xfb, 0x0f, 0xea, 0x75, 0xcd, 0xd1, 0x46, 0x3b, 0x7f, 0x33, 0x98, 0xe8, 0xe0,
];
const TAG_PERIOD_700_STREAM_7: [u8; 16] = [
    0xfe, 0x74, 0x8c, 0x95, 0xa8, 0x08, 0x9f, 0x8e, 0x96, 0x46, 0x54, 0xef, 0x0a, 0xce, 0xa5, 0xa8,
];

fn keys(role: Role) -> PeriodKeys {
    PeriodKeys::initial(&ROOT_KEY, &TOR, role, TIMESTAMP_MS).expect("the example derives")
}

// "Period zero starts at the Unix epoch" and a period lasts D + L seconds.
#[test]
fn periods_are_counted_from_the_unix_epoch() {
    assert_eq!(TOR.period_at(0), 0);
    assert_eq!(TOR.period_at(90_000 * 1_000 - 1), 0);
    assert_eq!(TOR.period_at(90_000 * 1_000), 1);
    assert_eq!(TOR.period_at(TIMESTAMP_MS), 700);
}

// The table in §4 is normative, so the numbers in it are a test and not a
// comment: peers that disagree here derive different keys and see a network
// that looks broken.
#[test]
fn the_period_lengths_are_the_ones_the_table_fixes() {
    assert_eq!(TOR.period_seconds(), 25 * 3600);
    assert_eq!(MEDIA.period_seconds(), 31 * 24 * 3600);
    assert_eq!(RELAY.period_seconds(), 31 * 24 * 3600);
}

// "The initial keys are the keys of the period before the one containing T."
#[test]
fn the_initial_keys_belong_to_the_period_before_the_timestamp() {
    assert_eq!(keys(Role::A).period, 699);
}

#[test]
fn the_initial_keys_match_the_specification() {
    let a = keys(Role::A);
    assert_eq!(a.outgoing.tag_key, A_TAG_KEY_INITIAL);
    assert_eq!(a.outgoing.header_key, A_HEADER_KEY_INITIAL);
    assert_eq!(a.incoming.tag_key, B_TAG_KEY_INITIAL);
    assert_eq!(a.incoming.header_key, B_HEADER_KEY_INITIAL);
}

// "each peer's outgoing keys are the other's incoming keys"
#[test]
fn the_roles_are_mirror_images() {
    let a = keys(Role::A);
    let b = keys(Role::B);
    assert_eq!(a.outgoing, b.incoming);
    assert_eq!(a.incoming, b.outgoing);
}

// "key := KDF(key, ROTATE, int_64(P))", once per period.
#[test]
fn rotation_matches_the_specification() {
    let at_700 = keys(Role::A).rotate_to(700).expect("one period forward");
    assert_eq!(at_700.period, 700);
    assert_eq!(at_700.outgoing.tag_key, A_TAG_KEY_PERIOD_700);

    let at_701 = at_700.rotate_to(701).expect("one more");
    assert_eq!(at_701.outgoing.tag_key, A_TAG_KEY_PERIOD_701);
}

// Rotating in one step and rotating period by period must agree, or a device
// that was offline derives different keys from one that was not.
#[test]
fn rotating_in_one_step_equals_rotating_period_by_period() {
    let stepwise = keys(Role::A)
        .rotate_to(700)
        .and_then(|k| k.rotate_to(701))
        .expect("stepwise");
    let in_one = keys(Role::A).rotate_to(701).expect("in one");
    assert_eq!(stepwise, in_one);
}

#[test]
fn rotating_to_the_same_period_changes_nothing() {
    let start = keys(Role::A);
    assert_eq!(start.rotate_to(start.period), Ok(start));
}

// The derivation is one-way. Being unable to go back is the forward secrecy,
// not a safety check that could be relaxed.
#[test]
fn rotation_never_goes_backwards() {
    let start = keys(Role::A);
    assert_eq!(
        start.rotate_to(698),
        Err(Error::PeriodInThePast {
            current: 699,
            requested: 698
        })
    );
}

// "An implementation MUST bound how many periods it will rotate in one step,
// and the bound MUST be at least 1024." The period comes from a clock, and a
// clock can be moved by someone else.
#[test]
fn rotating_further_than_the_bound_is_refused() {
    let start = keys(Role::A);
    assert!(start.rotate_to(start.period + MAX_ROTATIONS).is_ok());
    assert_eq!(
        start.rotate_to(start.period + MAX_ROTATIONS + 1),
        Err(Error::TooFarAhead {
            periods: MAX_ROTATIONS + 1
        })
    );
    assert_eq!(
        start.rotate_to(u64::MAX),
        Err(Error::TooFarAhead {
            periods: u64::MAX - 699
        })
    );
}

#[test]
fn a_timestamp_in_period_zero_is_refused() {
    assert_eq!(
        PeriodKeys::initial(&ROOT_KEY, &TOR, Role::A, 0),
        Err(Error::TimestampTooEarly)
    );
}

// "the first TAG_LEN bytes of PRF(k, int_16(protocol_version) ||
// int_64(stream_number))"
#[test]
fn a_tag_matches_the_specification() {
    let at_700 = keys(Role::A).rotate_to(700).expect("one period forward");
    let value = tag(&at_700.outgoing.tag_key, STREAM_NUMBER);
    assert_eq!(value, TAG_PERIOD_700_STREAM_7);
    assert_eq!(value.len(), TAG_LEN);
}

#[test]
fn every_stream_gets_its_own_tag() {
    let key = keys(Role::A).outgoing.tag_key;
    assert_ne!(tag(&key, 0), tag(&key, 1));
    assert_ne!(tag(&key, 7), tag(&keys(Role::B).outgoing.tag_key, 7));
}
