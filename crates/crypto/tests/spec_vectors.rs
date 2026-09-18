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

// --- PRF and KDF ----------------------------------------------------------
//
// Spec: `spec/05-primitives.md` §2 and §3. Vectors from scripts/vektoren.py,
// oracle CPython hashlib with the key argument, which is BLAKE2b's own keying
// and not a construction of ours.

const KEY: [u8; 32] = [0x44; 32];

const PRF_OF_KEY_AND_ABC: [u8; 32] = [
    0x1c, 0xd5, 0x7e, 0xa0, 0x11, 0xa5, 0x3c, 0x29, 0x87, 0xb3, 0x07, 0xa6, 0x24, 0xd1, 0x09, 0x10,
    0x0c, 0xe8, 0xe6, 0xf4, 0x2a, 0xa4, 0x99, 0x0a, 0xe0, 0x2c, 0xb1, 0x6e, 0x44, 0x89, 0x60, 0xd1,
];
const KDF_OF_KEY_AND_A_BC: [u8; 32] = [
    0x7d, 0xb7, 0x6a, 0x3a, 0x12, 0x81, 0x90, 0x8d, 0xd6, 0xc2, 0xf8, 0x40, 0x1c, 0xf1, 0xfe, 0xee,
    0xa8, 0x1b, 0xb8, 0x3c, 0xbb, 0xdb, 0x3e, 0x49, 0xc1, 0x78, 0x43, 0x49, 0x2d, 0xff, 0xa8, 0x67,
];

#[test]
fn the_prf_is_keyed_blake2b_over_the_message_as_given() {
    assert_eq!(onestein_crypto::prf(&KEY, b"abc"), PRF_OF_KEY_AND_ABC);
}

#[test]
fn the_kdf_frames_its_arguments_like_the_hash_does() {
    assert_eq!(
        onestein_crypto::kdf(&KEY, &[b"a", b"bc"]),
        KDF_OF_KEY_AND_A_BC
    );
}

// The difference between the two is the whole reason both exist: the PRF
// takes the message as given, so a caller who concatenates variable-length
// values with it can have the boundary moved.
#[test]
fn the_kdf_is_not_the_prf_of_the_concatenation() {
    assert_ne!(
        onestein_crypto::kdf(&KEY, &[b"a", b"bc"]),
        onestein_crypto::prf(&KEY, b"abc")
    );
    assert_ne!(
        onestein_crypto::kdf(&KEY, &[b"a", b"bc"]),
        onestein_crypto::kdf(&KEY, &[b"ab", b"c"])
    );
}

// A keyed function with a different key is a different function. Stated as a
// test because everything in the transport layer rests on it.
#[test]
fn a_different_key_gives_a_different_output() {
    assert_ne!(
        onestein_crypto::prf(&KEY, b"abc"),
        onestein_crypto::prf(&[0x45; 32], b"abc")
    );
}
