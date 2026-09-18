//! A whole handshake between two devices.
//!
//! No foreign oracle: X25519 comes from x25519-dalek and ML-KEM-768 from
//! ml-kem, both with their own test vectors. What is tested here is that the
//! two sides, driven only by the documented steps, arrive at the same root
//! key, and that they do not when anything is changed.
//!
//! Spec: `spec/30-handshake.md` §4 and §5.

use onestein_handshake::{
    Error, KEM_SEED_LEN, KeyPair, Role, Secrets, Transcript, X25519_LEN, confirmation, encapsulate,
    root_key,
};

const IDENTITY_ID_A: [u8; 32] = [0x01; 32];
const IDENTITY_ID_B: [u8; 32] = [0x02; 32];
const DEVICE_SIGNING_A: [u8; 32] = [0x03; 32];
const DEVICE_SIGNING_B: [u8; 32] = [0x04; 32];

fn pair(byte: u8) -> KeyPair {
    KeyPair::from_seeds(&[byte; X25519_LEN], &[byte; KEM_SEED_LEN])
}

/// Runs the four steps and returns both sides' root keys.
fn run(tamper_ct_static_b: bool) -> ([u8; 32], [u8; 32]) {
    let static_a = pair(0x11);
    let static_b = pair(0x22);
    let ephemeral_a = pair(0x33);
    let ephemeral_b = pair(0x44);

    // B encapsulates to A's ephemeral and static keys (step 2).
    let (ct_ephemeral_b, kem_ephemeral_b) =
        encapsulate(&ephemeral_a.kem_encapsulation_key(), &[0x55; 32]).expect("A's ephemeral key");
    let (mut ct_static_b, kem_static_b) =
        encapsulate(&static_a.kem_encapsulation_key(), &[0x66; 32]).expect("A's static key");
    if tamper_ct_static_b {
        if let Some(byte) = ct_static_b.first_mut() {
            *byte ^= 1;
        }
    }

    // A encapsulates to B's keys (step 3).
    let (ct_ephemeral_a, kem_ephemeral_a) =
        encapsulate(&ephemeral_b.kem_encapsulation_key(), &[0x77; 32]).expect("B's ephemeral key");
    let (ct_static_a, kem_static_a) =
        encapsulate(&static_b.kem_encapsulation_key(), &[0x88; 32]).expect("B's static key");

    let dh_static_pub_a = static_a.x25519_public();
    let dh_static_pub_b = static_b.x25519_public();
    let kem_static_pub_a = static_a.kem_encapsulation_key();
    let kem_static_pub_b = static_b.kem_encapsulation_key();
    let dh_ephemeral_pub_a = ephemeral_a.x25519_public();
    let dh_ephemeral_pub_b = ephemeral_b.x25519_public();
    let kem_ephemeral_pub_a = ephemeral_a.kem_encapsulation_key();
    let kem_ephemeral_pub_b = ephemeral_b.kem_encapsulation_key();

    let transcript = Transcript {
        identity_id_a: &IDENTITY_ID_A,
        identity_id_b: &IDENTITY_ID_B,
        device_signing_pub_a: &DEVICE_SIGNING_A,
        device_signing_pub_b: &DEVICE_SIGNING_B,
        dh_static_pub_a: &dh_static_pub_a,
        dh_static_pub_b: &dh_static_pub_b,
        kem_static_pub_a: &kem_static_pub_a,
        kem_static_pub_b: &kem_static_pub_b,
        dh_ephemeral_pub_a: &dh_ephemeral_pub_a,
        dh_ephemeral_pub_b: &dh_ephemeral_pub_b,
        kem_ephemeral_pub_a: &kem_ephemeral_pub_a,
        kem_ephemeral_pub_b: &kem_ephemeral_pub_b,
        ct_ephemeral_a: &ct_ephemeral_a,
        ct_ephemeral_b: &ct_ephemeral_b,
        ct_static_a: &ct_static_a,
        ct_static_b: &ct_static_b,
    };

    // A's view: it decapsulates what B sent and computes its own agreements.
    let a_secrets = Secrets {
        dh_ephemeral: ephemeral_a
            .agree(&ephemeral_b.x25519_public())
            .expect("not degenerate"),
        dh_ephemeral_static: ephemeral_a
            .agree(&static_b.x25519_public())
            .expect("not degenerate"),
        dh_static_ephemeral: static_a
            .agree(&ephemeral_b.x25519_public())
            .expect("not degenerate"),
        kem_ephemeral_a,
        kem_ephemeral_b: ephemeral_a.decapsulate(&ct_ephemeral_b),
        kem_static_a,
        kem_static_b: static_a.decapsulate(&ct_static_b),
    };

    // B's view: the mirror image, one side encapsulating where the other
    // decapsulated.
    let b_secrets = Secrets {
        dh_ephemeral: ephemeral_b
            .agree(&ephemeral_a.x25519_public())
            .expect("not degenerate"),
        dh_ephemeral_static: static_b
            .agree(&ephemeral_a.x25519_public())
            .expect("not degenerate"),
        dh_static_ephemeral: ephemeral_b
            .agree(&static_a.x25519_public())
            .expect("not degenerate"),
        kem_ephemeral_a: ephemeral_b.decapsulate(&ct_ephemeral_a),
        kem_ephemeral_b,
        kem_static_a: static_b.decapsulate(&ct_static_a),
        kem_static_b,
    };

    (
        root_key(&a_secrets, &transcript),
        root_key(&b_secrets, &transcript),
    )
}

#[test]
fn both_sides_arrive_at_the_same_root_key() {
    let (a, b) = run(false);
    assert_eq!(a, b);
    assert_ne!(a, [0u8; 32]);
    assert_eq!(confirmation(&a, Role::A), confirmation(&b, Role::A));
    assert_eq!(confirmation(&a, Role::B), confirmation(&b, Role::B));
}

// ML-KEM rejects implicitly: a tampered ciphertext decapsulates to a
// different secret rather than to an error. The handshake has to notice at
// the confirmation, and this is the test that it does.
#[test]
fn a_tampered_ciphertext_is_caught_by_the_confirmation() {
    let (a, b) = run(true);
    assert_ne!(a, b);
    assert_ne!(confirmation(&a, Role::A), confirmation(&b, Role::A));
}

// "An X25519 agreement that comes out all zeroes aborts the handshake."
#[test]
fn a_small_order_public_key_is_refused() {
    let keys = pair(0x99);
    assert_eq!(
        keys.agree(&[0u8; X25519_LEN]),
        Err(Error::DegenerateSharedSecret)
    );
}

// The same seeds must give the same keys, or nothing can be tested and a
// device could not be restored from a backup of its seed.
#[test]
fn key_generation_is_deterministic() {
    assert_eq!(pair(0x11).x25519_public(), pair(0x11).x25519_public());
    assert_eq!(
        pair(0x11).kem_encapsulation_key(),
        pair(0x11).kem_encapsulation_key()
    );
    assert_ne!(pair(0x11).x25519_public(), pair(0x12).x25519_public());
}

// Encapsulation takes its randomness as an argument, so the same randomness
// gives the same ciphertext and different randomness does not.
#[test]
fn encapsulation_uses_the_randomness_it_is_given() {
    let keys = pair(0xaa);
    let key = keys.kem_encapsulation_key();
    let (ct_one, secret_one) = encapsulate(&key, &[0x01; 32]).expect("encapsulates");
    let (ct_two, secret_two) = encapsulate(&key, &[0x01; 32]).expect("encapsulates");
    let (ct_three, secret_three) = encapsulate(&key, &[0x02; 32]).expect("encapsulates");

    assert_eq!(ct_one, ct_two);
    assert_eq!(secret_one, secret_two);
    assert_ne!(ct_one, ct_three);
    assert_ne!(secret_one, secret_three);
    assert_eq!(keys.decapsulate(&ct_one), secret_one);
}
