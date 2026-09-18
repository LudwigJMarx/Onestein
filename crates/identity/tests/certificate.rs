//! Device certificates.
//!
//! No foreign oracle for the signatures: Ed25519 comes from ed25519-dalek and
//! ML-DSA-65 from ml-dsa, both with their own vectors. What is tested here is
//! the structure around them, and above all that **both** signatures are
//! required, which a happy path would never reveal.
//!
//! Spec: `spec/40-identity.md` §4.

use onestein_bdf::{Value, from_bytes_canonical};
use onestein_identity::{
    DeviceCertificate, Error, IdentityId, KEM_ENCAPSULATION_KEY_LEN, RootKeys, X25519_LEN,
    verify_certificate,
};

/// A dictionary, or nothing: a test that panics on the wrong shape is a test
/// clippy refuses, and `expect` says the same thing at the call site.
fn dictionary(value: Value) -> Option<Vec<(String, Value)>> {
    match value {
        Value::Dict(entries) => Some(entries),
        _ => None,
    }
}

fn root() -> RootKeys {
    RootKeys::from_seeds(&[0x11; 32], &[0x22; 32])
}

fn certificate(root: &RootKeys) -> DeviceCertificate {
    DeviceCertificate {
        identity_id: root.identity_id().expect("derives"),
        device_signing_pub: [0x33; 32],
        dh_static_pub: [0x44; X25519_LEN],
        kem_static_pub: [0x55; KEM_ENCAPSULATION_KEY_LEN],
        epoch: 7,
        from_ms: 1_600_000_000_000,
    }
}

// The encoding is what gets signed, so it has to be canonical: keys sorted,
// lengths minimal. Strict parsing is the check (`10-encoding.md` §2.3).
#[test]
fn the_encoding_is_canonical_and_carries_the_fields_the_table_names() {
    let root = root();
    let encoded = certificate(&root).encode().expect("encodes");
    let parsed = from_bytes_canonical(&encoded).expect("strictly canonical");

    let entries = dictionary(parsed).expect("a certificate is a dictionary");
    let keys: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(keys, vec!["dev", "dh", "epoch", "from", "id", "kem", "v"]);
    assert!(entries.contains(&("v".to_owned(), Value::Int(1))));
    assert!(entries.contains(&("epoch".to_owned(), Value::Int(7))));
}

#[test]
fn a_signed_certificate_verifies_against_the_root_keys() {
    let root = root();
    let subject = certificate(&root);
    let container = root.sign_certificate(&subject).expect("signs");

    let verified = verify_certificate(&container, &root.ed25519_public(), &root.mldsa_public());
    assert_eq!(verified, Ok(subject));
}

#[test]
fn another_identity_does_not_verify_it() {
    let root = root();
    let container = root.sign_certificate(&certificate(&root)).expect("signs");
    let stranger = RootKeys::from_seeds(&[0x99; 32], &[0x88; 32]);

    assert!(
        verify_certificate(
            &container,
            &stranger.ed25519_public(),
            &stranger.mldsa_public()
        )
        .is_err()
    );
}

// "A verifier MUST check that the `id` field equals the identifier derived
// from the root keys it is verifying against."
#[test]
fn a_certificate_naming_another_identity_is_refused() {
    let root = root();
    let mut lying = certificate(&root);
    lying.identity_id = IdentityId::derive(&[0xaa; 32], &[0xbb; 1952]).expect("derives");
    let container = root.sign_certificate(&lying).expect("signs");

    assert_eq!(
        verify_certificate(&container, &root.ed25519_public(), &root.mldsa_public()),
        Err(Error::WrongIdentity)
    );
}

/// Flips a byte inside one field of the container, leaving the rest intact.
fn tamper(container: &[u8], field: &str) -> Vec<u8> {
    let entries = from_bytes_canonical(container)
        .ok()
        .and_then(dictionary)
        .expect("a container is a dictionary");
    let altered: Vec<(String, Value)> = entries
        .into_iter()
        .map(|(key, value)| match (key.as_str() == field, value) {
            (true, Value::Raw(mut bytes)) => {
                if let Some(byte) = bytes.first_mut() {
                    *byte ^= 1;
                }
                (key, Value::Raw(bytes))
            }
            (_, value) => (key, value),
        })
        .collect();
    onestein_bdf::to_bytes(&Value::Dict(altered))
}

// The two tests that matter. An implementation that checked only the Ed25519
// signature would pass every test above, and would hand a quantum adversary
// the ability to certify a device of its own.
#[test]
fn a_broken_ed25519_signature_is_refused() {
    let root = root();
    let container = root.sign_certificate(&certificate(&root)).expect("signs");
    assert_eq!(
        verify_certificate(
            &tamper(&container, "e"),
            &root.ed25519_public(),
            &root.mldsa_public()
        ),
        Err(Error::BadSignature)
    );
}

#[test]
fn a_broken_mldsa_signature_is_refused() {
    let root = root();
    let container = root.sign_certificate(&certificate(&root)).expect("signs");
    assert_eq!(
        verify_certificate(
            &tamper(&container, "p"),
            &root.ed25519_public(),
            &root.mldsa_public()
        ),
        Err(Error::BadSignature)
    );
}

// Altering the certificate itself invalidates both signatures, which is the
// point of signing the bytes rather than a parsed structure.
#[test]
fn an_altered_certificate_is_refused() {
    let root = root();
    let container = root.sign_certificate(&certificate(&root)).expect("signs");
    assert_eq!(
        verify_certificate(
            &tamper(&container, "c"),
            &root.ed25519_public(),
            &root.mldsa_public()
        ),
        Err(Error::BadSignature)
    );
}

#[test]
fn a_container_that_is_not_canonical_is_refused() {
    let root = root();
    let container = root.sign_certificate(&certificate(&root)).expect("signs");
    let entries = from_bytes_canonical(&container)
        .ok()
        .and_then(dictionary)
        .expect("a container is a dictionary");
    let reversed: Vec<(String, Value)> = entries.into_iter().rev().collect();
    let unsorted = onestein_bdf::to_bytes(&Value::Dict(reversed));

    assert_eq!(
        verify_certificate(&unsorted, &root.ed25519_public(), &root.mldsa_public()),
        Err(Error::Malformed)
    );
}

// The same seeds rebuild the same identity, which is what recovery rests on.
#[test]
fn root_keys_are_deterministic() {
    assert_eq!(root().ed25519_public(), root().ed25519_public());
    assert_eq!(root().mldsa_public(), root().mldsa_public());
    assert_eq!(root().identity_id(), root().identity_id());
    assert_ne!(
        root().ed25519_public(),
        RootKeys::from_seeds(&[0x12; 32], &[0x22; 32]).ed25519_public()
    );
}
