//! The key schedule.
//!
//! Expected values from `scripts/vektoren.py` (CPython hashlib). The seven
//! secrets and the public values are fill patterns of the right length: they
//! stand in for what X25519 and ML-KEM produce, so that the schedule is
//! checkable without those primitives. Whether the primitives are wired up
//! correctly is `handshake.rs`.
//!
//! Spec: `spec/30-handshake.md` §5.

use onestein_handshake::{
    KEM_CIPHERTEXT_LEN, KEM_ENCAPSULATION_KEY_LEN, Role, Secrets, Transcript, X25519_LEN,
    confirmation, root_key,
};

const DH_EPHEMERAL: [u8; 32] = [0xa0; 32];
const DH_EPHEMERAL_STATIC: [u8; 32] = [0xa1; 32];
const DH_STATIC_EPHEMERAL: [u8; 32] = [0xa2; 32];
const KEM_EPHEMERAL_A: [u8; 32] = [0xb0; 32];
const KEM_EPHEMERAL_B: [u8; 32] = [0xb1; 32];
const KEM_STATIC_A: [u8; 32] = [0xb2; 32];
const KEM_STATIC_B: [u8; 32] = [0xb3; 32];

const IDENTITY_ID_A: [u8; 32] = [0xc0; 32];
const IDENTITY_ID_B: [u8; 32] = [0xc1; 32];
const DEVICE_SIGNING_A: [u8; 32] = [0xc2; 32];
const DEVICE_SIGNING_B: [u8; 32] = [0xc3; 32];
const DH_STATIC_PUB_A: [u8; X25519_LEN] = [0xc4; X25519_LEN];
const DH_STATIC_PUB_B: [u8; X25519_LEN] = [0xc5; X25519_LEN];
const DH_EPHEMERAL_PUB_A: [u8; X25519_LEN] = [0xc6; X25519_LEN];
const DH_EPHEMERAL_PUB_B: [u8; X25519_LEN] = [0xc7; X25519_LEN];
const KEM_STATIC_PUB_A: [u8; KEM_ENCAPSULATION_KEY_LEN] = [0xd0; KEM_ENCAPSULATION_KEY_LEN];
const KEM_STATIC_PUB_B: [u8; KEM_ENCAPSULATION_KEY_LEN] = [0xd1; KEM_ENCAPSULATION_KEY_LEN];
const KEM_EPHEMERAL_PUB_A: [u8; KEM_ENCAPSULATION_KEY_LEN] = [0xd2; KEM_ENCAPSULATION_KEY_LEN];
const KEM_EPHEMERAL_PUB_B: [u8; KEM_ENCAPSULATION_KEY_LEN] = [0xd3; KEM_ENCAPSULATION_KEY_LEN];
const CT_EPHEMERAL_A: [u8; KEM_CIPHERTEXT_LEN] = [0xe0; KEM_CIPHERTEXT_LEN];
const CT_EPHEMERAL_B: [u8; KEM_CIPHERTEXT_LEN] = [0xe1; KEM_CIPHERTEXT_LEN];
const CT_STATIC_A: [u8; KEM_CIPHERTEXT_LEN] = [0xe2; KEM_CIPHERTEXT_LEN];
const CT_STATIC_B: [u8; KEM_CIPHERTEXT_LEN] = [0xe3; KEM_CIPHERTEXT_LEN];

const ROOT_KEY: [u8; 32] = [
    0x1c, 0x65, 0x13, 0x44, 0xdb, 0x39, 0x58, 0x3e, 0xdd, 0xc5, 0x5b, 0x0f, 0xf2, 0x88, 0x0c, 0x30,
    0x3e, 0xb5, 0x9e, 0x5a, 0x05, 0xe4, 0xc8, 0x8e, 0xd1, 0xfe, 0xf2, 0xf2, 0x78, 0xe5, 0x72, 0xea,
];
const CONFIRMATION_A: [u8; 32] = [
    0x23, 0x75, 0x9a, 0x11, 0xbe, 0xa0, 0xd1, 0x4d, 0xba, 0xf5, 0x9d, 0x24, 0xe6, 0x90, 0x3a, 0xdc,
    0x97, 0x2b, 0xd8, 0x6c, 0xf6, 0xaf, 0x35, 0xfa, 0x2f, 0xa5, 0x93, 0xb5, 0x53, 0x5b, 0xe6, 0x33,
];
const CONFIRMATION_B: [u8; 32] = [
    0x57, 0xd6, 0x16, 0xa4, 0x69, 0xe3, 0xd6, 0xc4, 0x4a, 0x9d, 0x95, 0xdb, 0x54, 0x26, 0xaa, 0x7b,
    0x2f, 0xc2, 0xc8, 0xa3, 0xc2, 0x4e, 0x56, 0xf1, 0x27, 0x90, 0xd4, 0x41, 0x45, 0x1d, 0xae, 0x94,
];

fn secrets() -> Secrets {
    Secrets {
        dh_ephemeral: DH_EPHEMERAL,
        dh_ephemeral_static: DH_EPHEMERAL_STATIC,
        dh_static_ephemeral: DH_STATIC_EPHEMERAL,
        kem_ephemeral_a: KEM_EPHEMERAL_A,
        kem_ephemeral_b: KEM_EPHEMERAL_B,
        kem_static_a: KEM_STATIC_A,
        kem_static_b: KEM_STATIC_B,
    }
}

fn transcript() -> Transcript<'static> {
    Transcript {
        identity_id_a: &IDENTITY_ID_A,
        identity_id_b: &IDENTITY_ID_B,
        device_signing_pub_a: &DEVICE_SIGNING_A,
        device_signing_pub_b: &DEVICE_SIGNING_B,
        dh_static_pub_a: &DH_STATIC_PUB_A,
        dh_static_pub_b: &DH_STATIC_PUB_B,
        kem_static_pub_a: &KEM_STATIC_PUB_A,
        kem_static_pub_b: &KEM_STATIC_PUB_B,
        dh_ephemeral_pub_a: &DH_EPHEMERAL_PUB_A,
        dh_ephemeral_pub_b: &DH_EPHEMERAL_PUB_B,
        kem_ephemeral_pub_a: &KEM_EPHEMERAL_PUB_A,
        kem_ephemeral_pub_b: &KEM_EPHEMERAL_PUB_B,
        ct_ephemeral_a: &CT_EPHEMERAL_A,
        ct_ephemeral_b: &CT_EPHEMERAL_B,
        ct_static_a: &CT_STATIC_A,
        ct_static_b: &CT_STATIC_B,
    }
}

#[test]
fn the_root_key_matches_the_specification() {
    assert_eq!(root_key(&secrets(), &transcript()), ROOT_KEY);
}

#[test]
fn the_confirmations_match_the_specification() {
    assert_eq!(confirmation(&ROOT_KEY, Role::A), CONFIRMATION_A);
    assert_eq!(confirmation(&ROOT_KEY, Role::B), CONFIRMATION_B);
    assert_ne!(CONFIRMATION_A, CONFIRMATION_B);
}

// Every secret is in the key. Dropping one would leave a handshake that looks
// hybrid and is not, and no test of the happy path would notice.
#[test]
fn every_secret_changes_the_root_key() {
    let base = root_key(&secrets(), &transcript());
    let fields: [fn(&mut Secrets); 7] = [
        |s| s.dh_ephemeral = [0; 32],
        |s| s.dh_ephemeral_static = [0; 32],
        |s| s.dh_static_ephemeral = [0; 32],
        |s| s.kem_ephemeral_a = [0; 32],
        |s| s.kem_ephemeral_b = [0; 32],
        |s| s.kem_static_a = [0; 32],
        |s| s.kem_static_b = [0; 32],
    ];
    for change in fields {
        let mut altered = secrets();
        change(&mut altered);
        assert_ne!(root_key(&altered, &transcript()), base);
    }
}

// The transcript is in the key so that an adversary who alters any public
// value on the wire is found out at the confirmation rather than never.
#[test]
fn altering_the_transcript_changes_the_root_key() {
    let base = root_key(&secrets(), &transcript());

    let other_id = [0xff; 32];
    let mut altered = transcript();
    altered.identity_id_a = &other_id;
    assert_ne!(root_key(&secrets(), &altered), base);

    let other_ct = [0xff; KEM_CIPHERTEXT_LEN];
    let mut altered = transcript();
    altered.ct_static_b = &other_ct;
    assert_ne!(root_key(&secrets(), &altered), base);

    let other_key = [0xff; KEM_ENCAPSULATION_KEY_LEN];
    let mut altered = transcript();
    altered.kem_ephemeral_pub_b = &other_key;
    assert_ne!(root_key(&secrets(), &altered), base);
}

// Swapping the two sides must not produce the same key, or the roles would be
// decoration.
#[test]
fn the_two_sides_are_not_interchangeable() {
    let base = root_key(&secrets(), &transcript());
    let mut swapped = transcript();
    swapped.identity_id_a = &IDENTITY_ID_B;
    swapped.identity_id_b = &IDENTITY_ID_A;
    assert_ne!(root_key(&secrets(), &swapped), base);
}
