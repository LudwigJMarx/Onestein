//! Queue names, keys and proofs.
//!
//! Spec: `spec/60-relay.md` §2, §3.

use onestein_relay::{Direction, Error, MIN_CHALLENGE_LEN, PROOF_LEN, QueueKeys, Right, queue_id};

const ROOT_KEY: [u8; 32] = [0x44; 32];
const RELAY: &str = "relay.example";
const CHALLENGE: &[u8] = b"sixteen bytes at least";

// "Two contacts have two queues per relay, one each way."
#[test]
fn the_two_directions_are_different_queues() {
    let a = queue_id(&ROOT_KEY, Direction::AToB, RELAY, 7);
    let b = queue_id(&ROOT_KEY, Direction::BToA, RELAY, 7);
    assert_ne!(a, b);
    assert_eq!(a, queue_id(&ROOT_KEY, Direction::AToB, RELAY, 7));
}

// "Queue identifiers change every period. A relay watching one identifier
// watches one month of one direction of one relationship."
#[test]
fn a_queue_identifier_changes_with_period_relay_and_root_key() {
    let base = queue_id(&ROOT_KEY, Direction::AToB, RELAY, 7);
    assert_ne!(base, queue_id(&ROOT_KEY, Direction::AToB, RELAY, 8));
    assert_ne!(
        base,
        queue_id(&ROOT_KEY, Direction::AToB, "other.example", 7)
    );
    assert_ne!(base, queue_id(&[0x45; 32], Direction::AToB, RELAY, 7));
}

fn keys() -> QueueKeys {
    QueueKeys::derive(&ROOT_KEY, Direction::AToB, RELAY, 7)
}

#[test]
fn a_proof_verifies_for_the_challenge_it_was_made_for() {
    let keys = keys();
    let registration = keys.registration();
    let proof = keys.prove(Right::Write, CHALLENGE).expect("proves");
    assert_eq!(registration.check(Right::Write, CHALLENGE, &proof), Ok(()));
}

// A challenge is good once. A proof that verified for one challenge must not
// verify for another, or a relay operator could replay what it watched.
#[test]
fn a_proof_does_not_carry_to_another_challenge() {
    let keys = keys();
    let proof = keys.prove(Right::Write, CHALLENGE).expect("proves");
    assert_eq!(
        keys.registration()
            .check(Right::Write, b"another challenge!!", &proof),
        Err(Error::BadProof)
    );
}

// "The writer cannot read its own queue and the reader cannot write to it."
#[test]
fn the_two_rights_do_not_substitute_for_each_other() {
    let keys = keys();
    let registration = keys.registration();
    let write_proof = keys.prove(Right::Write, CHALLENGE).expect("proves");
    let read_proof = keys.prove(Right::Read, CHALLENGE).expect("proves");

    assert_ne!(write_proof, read_proof);
    assert_eq!(
        registration.check(Right::Read, CHALLENGE, &write_proof),
        Err(Error::BadProof)
    );
    assert_eq!(
        registration.check(Right::Write, CHALLENGE, &read_proof),
        Err(Error::BadProof)
    );
    assert_ne!(registration.write_public, registration.read_public);
}

// What the relay stores must not let it make proofs. This is the property the
// document claims, and the reason the scheme is signatures and not MACs.
#[test]
fn what_a_relay_stores_does_not_let_it_write() {
    let registration = keys().registration();
    let forged = [0x11; PROOF_LEN];
    assert_eq!(
        registration.check(Right::Write, CHALLENGE, &forged),
        Err(Error::BadProof)
    );

    // A different pair's public keys do not verify our proofs either.
    let stranger = QueueKeys::derive(&[0x99; 32], Direction::AToB, RELAY, 7).registration();
    let proof = keys().prove(Right::Write, CHALLENGE).expect("proves");
    assert_eq!(
        stranger.check(Right::Write, CHALLENGE, &proof),
        Err(Error::BadProof)
    );
}

// "the relay answers with a random challenge of at least 16 bytes"
#[test]
fn a_short_challenge_is_refused_on_both_sides() {
    let keys = keys();
    let short = [0u8; MIN_CHALLENGE_LEN - 1];
    assert_eq!(
        keys.prove(Right::Write, &short),
        Err(Error::ChallengeTooShort {
            given: MIN_CHALLENGE_LEN - 1
        })
    );
    assert_eq!(
        keys.registration()
            .check(Right::Write, &short, &[0u8; PROOF_LEN]),
        Err(Error::ChallengeTooShort {
            given: MIN_CHALLENGE_LEN - 1
        })
    );
}

#[test]
fn keys_change_with_the_period() {
    let now = keys().registration();
    let later = QueueKeys::derive(&ROOT_KEY, Direction::AToB, RELAY, 8).registration();
    assert_ne!(now.write_public, later.write_public);
    assert_ne!(now.read_public, later.read_public);
}
