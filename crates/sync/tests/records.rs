//! The five records, and the horizon.
//!
//! Spec: `spec/50-sync.md` §5, §7.

use onestein_sync::{
    Deliverability, Error, MessageId, SyncRecord, decode_records, deliverability, encode_record,
};

fn id(byte: u8) -> MessageId {
    MessageId::from_bytes([byte; 32])
}

#[test]
fn every_identifier_record_round_trips_with_its_type_byte() {
    let cases = [
        (SyncRecord::Ack(vec![id(1)]), 0),
        (SyncRecord::Offer(vec![id(1), id(2)]), 2),
        (SyncRecord::Request(vec![id(3)]), 3),
        (SyncRecord::Unavailable(vec![id(4), id(5), id(6)]), 4),
    ];
    for (record, expected_type) in cases {
        let encoded = encode_record(&record).expect("encodes");
        assert_eq!(encoded.get(1), Some(&expected_type));
        assert_eq!(decode_records(&encoded), Ok(vec![record]));
    }
}

// "The record's payload consists of one or more message identifiers."
#[test]
fn an_empty_identifier_list_is_refused() {
    assert_eq!(
        encode_record(&SyncRecord::Ack(vec![])),
        Err(Error::Malformed)
    );
    let empty = onestein_record::encode(1, 0, b"").expect("frames");
    assert_eq!(decode_records(&empty), Err(Error::Malformed));
}

#[test]
fn a_payload_that_is_not_whole_identifiers_is_refused() {
    let ragged = onestein_record::encode(1, 2, &[0u8; 33]).expect("frames");
    assert_eq!(decode_records(&ragged), Err(Error::Malformed));
}

#[test]
fn an_unknown_type_is_handed_over_and_another_version_is_not() {
    let unknown = onestein_record::encode(1, 42, b"later").expect("frames");
    assert_eq!(
        decode_records(&unknown),
        Ok(vec![SyncRecord::Unknown { record_type: 42 }])
    );

    let other_version = onestein_record::encode(2, 0, &[0u8; 32]).expect("frames");
    assert!(decode_records(&other_version).is_err());
}

// --- The horizon ----------------------------------------------------------
//
// "A message is delivered to its client when all its dependencies have been
// delivered", and "dependencies inside the horizon are satisfied by
// definition".

#[test]
fn a_message_without_dependencies_is_ready_and_complete() {
    assert_eq!(
        deliverability(&[], |_| None, |_| false),
        Deliverability::Ready {
            ancestry_incomplete: false
        }
    );
}

#[test]
fn every_dependency_delivered_means_ready() {
    let dependencies = [id(1), id(2)];
    assert_eq!(
        deliverability(&dependencies, |_| Some(false), |_| false),
        Deliverability::Ready {
            ancestry_incomplete: false
        }
    );
}

#[test]
fn a_missing_dependency_means_waiting() {
    let dependencies = [id(1), id(2)];
    assert_eq!(
        deliverability(
            &dependencies,
            |which| (*which == id(1)).then_some(false),
            |_| false
        ),
        Deliverability::Waiting
    );
}

// This is R9: a member that joined at a horizon can read what comes after it
// without ever having held what came before.
#[test]
fn a_dependency_inside_the_horizon_is_ready_but_incomplete() {
    let dependencies = [id(9)];
    assert_eq!(
        deliverability(&dependencies, |_| None, |which| *which == id(9)),
        Deliverability::Ready {
            ancestry_incomplete: true
        }
    );
}

// Incompleteness travels forward. A message resting on one that was itself
// delivered with a gap behind it is no better founded than that one.
#[test]
fn incomplete_ancestry_is_inherited() {
    let dependencies = [id(1)];
    assert_eq!(
        deliverability(&dependencies, |_| Some(true), |_| false),
        Deliverability::Ready {
            ancestry_incomplete: true
        }
    );
}

// The horizon does not rescue a dependency that is merely missing: it has to
// be named by the horizon, not absent from everything.
#[test]
fn the_horizon_only_covers_what_it_names() {
    let dependencies = [id(1), id(2)];
    assert_eq!(
        deliverability(&dependencies, |_| None, |which| *which == id(1)),
        Deliverability::Waiting
    );
}
