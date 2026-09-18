//! Recovery from a seed.
//!
//! The three derived seeds are checked against `scripts/vektoren.py`
//! (CPython hashlib). Everything else is the property that recovery exists
//! for: the same seed is the same identity, anywhere, later.
//!
//! Spec: `spec/40-identity.md` §6.

use onestein_identity::{
    DeviceCertificate, KEM_ENCAPSULATION_KEY_LEN, RecoverySeed, X25519_LEN, verify_certificate,
};

const RECOVERY_SEED: [u8; 32] = [0x5a; 32];

const ROOT_ED25519_SEED: [u8; 32] = [
    0x72, 0xd9, 0x7b, 0x64, 0xc4, 0xf0, 0x04, 0xb6, 0xa0, 0x6b, 0xe9, 0xbc, 0x89, 0x8c, 0x3b, 0xc2,
    0x01, 0xf4, 0xc7, 0x91, 0xf0, 0xf8, 0x7c, 0xfd, 0x7f, 0x13, 0xe9, 0x7e, 0x04, 0x56, 0xd9, 0x28,
];
const ROOT_MLDSA_SEED: [u8; 32] = [
    0x98, 0xde, 0x2a, 0x4d, 0x67, 0xaa, 0x83, 0x4c, 0x2b, 0xc9, 0x53, 0xc7, 0xca, 0x6c, 0x4d, 0x88,
    0x8f, 0xac, 0xfd, 0xd5, 0x63, 0x08, 0x4e, 0x42, 0xcd, 0x77, 0x32, 0x63, 0xe4, 0x68, 0xf6, 0x53,
];
const CONTACT_SEED: [u8; 32] = [
    0x9c, 0xae, 0x40, 0x44, 0xbe, 0x48, 0x73, 0xe5, 0x1b, 0x02, 0xe1, 0x80, 0xc4, 0xff, 0x20, 0x69,
    0x02, 0xd1, 0xc9, 0x6a, 0x54, 0xef, 0x32, 0x9c, 0x56, 0x1e, 0xcf, 0xf2, 0xbf, 0x86, 0x0b, 0x10,
];

fn seed() -> RecoverySeed {
    RecoverySeed::from_bytes(RECOVERY_SEED)
}

// "root_ed25519_seed = KDF(seed, ...)" and the two others.
#[test]
fn the_three_derived_seeds_match_the_specification() {
    assert_eq!(seed().root_ed25519_seed(), ROOT_ED25519_SEED);
    assert_eq!(seed().root_mldsa_seed(), ROOT_MLDSA_SEED);
    assert_eq!(seed().contact_secret(), CONTACT_SEED);
}

// Three labels, three different keys. A mix-up would make two of them share a
// secret, which no test of the happy path would show.
#[test]
fn the_three_seeds_differ_from_each_other_and_from_their_source() {
    let derived = [
        seed().root_ed25519_seed(),
        seed().root_mldsa_seed(),
        seed().contact_secret(),
    ];
    for (index, one) in derived.iter().enumerate() {
        assert_ne!(
            *one, RECOVERY_SEED,
            "derived key {index} is the seed itself"
        );
        for other in derived.iter().skip(index + 1) {
            assert_ne!(one, other);
        }
    }
}

// The property recovery exists for.
#[test]
fn the_same_seed_is_the_same_identity() {
    assert_eq!(seed().identity_id(), seed().identity_id());
    assert_eq!(seed().contact_public(), seed().contact_public());

    let other = RecoverySeed::from_bytes([0x5b; 32]);
    assert_ne!(seed().identity_id(), other.identity_id());
    assert_ne!(seed().contact_public(), other.contact_public());
}

// What recovery is for, end to end: a device is lost, the seed is typed into
// a new one, and a contact that holds only the old root keys accepts the new
// device's certificate.
#[test]
fn a_recovered_device_can_certify_itself_to_an_old_contact() {
    // What a contact wrote down long ago.
    let known_ed25519 = seed().root_keys().ed25519_public();
    let known_mldsa = seed().root_keys().mldsa_public();

    // A new device, on a new phone, from the same seed.
    let recovered = RecoverySeed::from_bytes(RECOVERY_SEED);
    let certificate = DeviceCertificate {
        identity_id: recovered.identity_id().expect("derives"),
        device_signing_pub: [0xcc; 32],
        dh_static_pub: [0xdd; X25519_LEN],
        kem_static_pub: [0xee; KEM_ENCAPSULATION_KEY_LEN],
        epoch: 12,
        from_ms: 1_700_000_000_000,
    };
    let container = recovered
        .root_keys()
        .sign_certificate(&certificate)
        .expect("signs");

    assert_eq!(
        verify_certificate(&container, &known_ed25519, &known_mldsa),
        Ok(certificate)
    );
}

// The contact public key is the X25519 public key of the contact secret, and
// not something else that happens to be 32 bytes.
#[test]
fn the_contact_public_key_belongs_to_the_contact_secret() {
    let secret = x25519_dalek::StaticSecret::from(seed().contact_secret());
    let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    assert_eq!(seed().contact_public(), public);
}
