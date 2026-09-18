//! Conformance vectors for identity identifiers.
//!
//! Expected values from `scripts/vektoren.py` (CPython hashlib). The keys are
//! fill patterns of the right length, not real keys.
//!
//! Spec: `spec/40-identity.md` §3.

use onestein_identity::{Error, IdentityId, ROOT_ED25519_LEN, ROOT_MLDSA_LEN};

const ROOT_ED25519: [u8; 32] = [0x11; 32];
const ROOT_MLDSA: [u8; 1952] = [0x22; 1952];

const IDENTITY_ID: [u8; 32] = [
    0x5a, 0x64, 0xaa, 0xfd, 0x01, 0x63, 0xba, 0x9f, 0x3a, 0xd8, 0x56, 0xe2, 0xe5, 0x17, 0x35, 0xa3,
    0x79, 0xea, 0x8d, 0x12, 0xf6, 0xc4, 0x85, 0x22, 0x3a, 0xe7, 0x15, 0xd5, 0x28, 0xe9, 0xbb, 0x9b,
];

// "identity_id = HASH("org.onestein.identity/IDENTITY_ID", int_8(version),
// root_ed25519_pub, root_mldsa_pub)"
#[test]
fn an_identity_identifier_matches_the_specification() {
    let id = IdentityId::derive(&ROOT_ED25519, &ROOT_MLDSA).expect("the example identity derives");
    assert_eq!(id.as_bytes(), &IDENTITY_ID);
}

// "Both root signatures are always produced and both MUST verify. A
// certificate that carries only one of them is refused." An identity with one
// key must not be expressible at all.
#[test]
fn a_key_of_the_wrong_length_is_refused() {
    assert_eq!(
        IdentityId::derive(&[0x11; 31], &ROOT_MLDSA),
        Err(Error::WrongKeyLength {
            expected: ROOT_ED25519_LEN,
            given: 31
        })
    );
    assert_eq!(
        IdentityId::derive(&ROOT_ED25519, &[]),
        Err(Error::WrongKeyLength {
            expected: ROOT_MLDSA_LEN,
            given: 0
        })
    );
}

// The identifier covers both keys, so changing either is another identity.
#[test]
fn both_keys_are_covered() {
    let base = IdentityId::derive(&ROOT_ED25519, &ROOT_MLDSA);
    assert_ne!(base, IdentityId::derive(&[0x12; 32], &ROOT_MLDSA));
    assert_ne!(base, IdentityId::derive(&ROOT_ED25519, &[0x23; 1952]));
}
