//! Conformance vectors for the BSP hash construction.
//!
//! The expected values are produced by `scripts/vektoren-bsp-hash.py`, which
//! uses CPython's `hashlib.blake2b`. That is an independent implementation of
//! BLAKE2b, not an independent implementation of Bramble: it proves that our
//! BLAKE2b and our framing agree with a second party's BLAKE2b, and nothing
//! about whether Briar computes the same identifiers. That is the Java
//! implementation's job and it is still open.
//!
//! Spec: BSP 1.4.

use onestein_crypto::{HASH_LEN, hash};

// Erzeugt von scripts/vektoren-bsp-hash.py, Oracle: CPython hashlib.
const HASH_OF_NOTHING: [u8; 32] = [
    0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99, 0xda, 0xa1,
    0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd, 0xf1, 0x2f, 0xe3, 0xa8,
];
const HASH_OF_ONE_EMPTY_ARGUMENT: [u8; 32] = [
    0x11, 0xda, 0x6d, 0x1f, 0x76, 0x1d, 0xdf, 0x9b, 0xdb, 0x4c, 0x9d, 0x6e, 0x53, 0x03, 0xeb, 0xd4,
    0x1f, 0x61, 0x85, 0x8d, 0x0a, 0x56, 0x47, 0xa1, 0xa7, 0xbf, 0xe0, 0x89, 0xbf, 0x92, 0x1b, 0xe9,
];
const HASH_OF_A_AND_BC: [u8; 32] = [
    0x98, 0x8d, 0x8e, 0xf2, 0xf8, 0xf0, 0x5e, 0x0d, 0x94, 0x51, 0xa5, 0xec, 0xd7, 0xe9, 0x56, 0xd9,
    0x2f, 0x5b, 0xb5, 0x05, 0x5d, 0x21, 0x6d, 0x4e, 0x65, 0x2e, 0xc8, 0x19, 0xdb, 0x3d, 0x67, 0xa6,
];

// "All hashes are HASH_LEN bytes." with HASH_LEN = 32 for BLAKE2b.
#[test]
fn a_hash_is_thirty_two_bytes() {
    assert_eq!(HASH_LEN, 32);
    assert_eq!(hash(&[b"anything"]).len(), 32);
}

// "HASH(x_1, ..., x_n) = H(int_32(len(x_1)) || x_1 || ... )" - with no
// arguments there is nothing to frame, so this is H of the empty string.
#[test]
fn no_arguments_hashes_the_empty_input() {
    assert_eq!(hash(&[]), HASH_OF_NOTHING);
}

// One empty argument still contributes its length prefix, so it differs from
// no argument at all.
#[test]
fn one_empty_argument_is_not_the_same_as_none() {
    assert_eq!(hash(&[b""]), HASH_OF_ONE_EMPTY_ARGUMENT);
    assert_ne!(hash(&[b""]), HASH_OF_NOTHING);
}

#[test]
fn two_arguments_are_framed_by_their_lengths() {
    assert_eq!(hash(&[b"a", b"bc"]), HASH_OF_A_AND_BC);
}

// The reason the length prefixes exist: without them an attacker could move
// the boundary between two arguments without changing the hash.
#[test]
fn moving_the_boundary_between_arguments_changes_the_hash() {
    assert_ne!(hash(&[b"a", b"bc"]), hash(&[b"ab", b"c"]));
    assert_ne!(hash(&[b"abc"]), hash(&[b"a", b"bc"]));
}
