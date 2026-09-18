//! Revocations, and the epoch rule around them.
//!
//! Spec: `spec/40-identity.md` §5.

use onestein_bdf::{Value, from_bytes_canonical};
use onestein_identity::{
    DeviceCertificate, Error, IdentityId, KEM_ENCAPSULATION_KEY_LEN, Revocation, RootKeys,
    X25519_LEN, accept_epoch, verify_certificate, verify_revocation,
};

fn root() -> RootKeys {
    RootKeys::from_seeds(&[0x11; 32], &[0x22; 32])
}

fn revocation(root: &RootKeys) -> Revocation {
    Revocation {
        identity_id: root.identity_id().expect("derives"),
        device_signing_pub: [0x33; 32],
        epoch: 8,
    }
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

// "revocation = canonical BDF over {v, id, dev, epoch}". No reason field.
#[test]
fn a_revocation_carries_four_fields_and_no_reason() {
    let root = root();
    let encoded = revocation(&root).encode().expect("encodes");
    let parsed = from_bytes_canonical(&encoded).expect("strictly canonical");

    let entries = match parsed {
        Value::Dict(entries) => entries,
        _ => Vec::new(),
    };
    let keys: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(keys, vec!["dev", "epoch", "id", "v"]);
}

#[test]
fn a_signed_revocation_verifies_against_the_root_keys() {
    let root = root();
    let subject = revocation(&root);
    let container = root.sign_revocation(&subject).expect("signs");

    assert_eq!(
        verify_revocation(&container, &root.ed25519_public(), &root.mldsa_public()),
        Ok(subject)
    );
}

// The reason the two structures have different labels. Without it, a
// certificate's signature would carry over to a revocation whose fields
// happen to line up, and a device could be revoked by replaying its own
// certificate, or resurrected by replaying its revocation.
#[test]
fn a_certificate_does_not_verify_as_a_revocation_or_the_other_way_round() {
    let root = root();
    let cert_container = root.sign_certificate(&certificate(&root)).expect("signs");
    let revocation_container = root.sign_revocation(&revocation(&root)).expect("signs");

    assert_eq!(
        verify_revocation(
            &cert_container,
            &root.ed25519_public(),
            &root.mldsa_public()
        ),
        Err(Error::BadSignature)
    );
    assert_eq!(
        verify_certificate(
            &revocation_container,
            &root.ed25519_public(),
            &root.mldsa_public()
        ),
        Err(Error::BadSignature)
    );
}

#[test]
fn a_revocation_naming_another_identity_is_refused() {
    let root = root();
    let mut lying = revocation(&root);
    lying.identity_id = IdentityId::derive(&[0xaa; 32], &[0xbb; 1952]).expect("derives");
    let container = root.sign_revocation(&lying).expect("signs");

    assert_eq!(
        verify_revocation(&container, &root.ed25519_public(), &root.mldsa_public()),
        Err(Error::WrongIdentity)
    );
}

#[test]
fn both_signatures_are_required_on_a_revocation_too() {
    let root = root();
    let container = root.sign_revocation(&revocation(&root)).expect("signs");

    for field in ["e", "p", "c"] {
        let entries = from_bytes_canonical(&container)
            .ok()
            .and_then(|value| match value {
                Value::Dict(entries) => Some(entries),
                _ => None,
            })
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
        let tampered = onestein_bdf::to_bytes(&Value::Dict(altered));

        assert_eq!(
            verify_revocation(&tampered, &root.ed25519_public(), &root.mldsa_public()),
            Err(Error::BadSignature),
            "tampering with {field} must be caught"
        );
    }
}

// "A certificate or revocation from a lower epoch is refused, silently."
#[test]
fn an_epoch_below_the_recorded_one_is_refused() {
    assert_eq!(
        accept_epoch(8, 7),
        Err(Error::EpochInThePast {
            recorded: 8,
            given: 7
        })
    );
}

// Equal is not lower: two devices certified in one epoch is ordinary.
#[test]
fn an_equal_epoch_is_accepted_and_the_record_does_not_move() {
    assert_eq!(accept_epoch(8, 8), Ok(8));
}

#[test]
fn a_higher_epoch_is_accepted_and_becomes_the_record() {
    assert_eq!(accept_epoch(8, 9), Ok(9));
    assert_eq!(accept_epoch(0, 1), Ok(1));
}

// The rule the epoch exists for: once a revocation at epoch 8 has been seen,
// the device's own certificate at epoch 7 can no longer be replayed to bring
// it back.
#[test]
fn an_old_certificate_cannot_resurrect_a_revoked_device() {
    let root = root();
    let revoked = revocation(&root);
    let old = certificate(&root);
    assert!(old.epoch < revoked.epoch);

    let recorded = accept_epoch(0, revoked.epoch).expect("the revocation moves the record");
    assert_eq!(
        accept_epoch(recorded, old.epoch),
        Err(Error::EpochInThePast {
            recorded: 8,
            given: 7
        })
    );
}
