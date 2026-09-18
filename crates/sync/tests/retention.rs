//! Retention policies.
//!
//! Spec: `spec/50-sync.md` §6.

use onestein_sync::{Error, MessageId, Retention};

const DAY: u64 = 24 * 60 * 60 * 1000;

fn id(byte: u8) -> MessageId {
    MessageId::from_bytes([byte; 32])
}

/// Five messages, received one day apart, newest last.
fn held() -> Vec<(MessageId, u64)> {
    (1..=5u8).map(|n| (id(n), u64::from(n) * DAY)).collect()
}

#[test]
fn every_policy_round_trips() {
    for policy in [
        Retention::All,
        Retention::Count(7),
        Retention::Age { days: 30 },
    ] {
        let encoded = policy.encode();
        assert_eq!(Retention::decode(&encoded), Ok(policy));
    }
}

#[test]
fn something_that_is_not_a_policy_is_refused() {
    assert_eq!(Retention::decode(b""), Err(Error::Malformed));
    assert_eq!(Retention::decode(&[0x00]), Err(Error::Malformed));
    assert_eq!(
        Retention::decode(&onestein_bdf::to_bytes(&onestein_bdf::Value::Str(
            "forever".to_owned()
        ))),
        Err(Error::Malformed)
    );
}

#[test]
fn keeping_everything_drops_nothing() {
    assert!(Retention::All.droppable(10 * DAY, &held()).is_empty());
}

// "keep at least the most recent n messages"
#[test]
fn a_count_keeps_the_newest_and_drops_the_rest() {
    let dropped = Retention::Count(2).droppable(10 * DAY, &held());
    assert_eq!(dropped, vec![id(1), id(2), id(3)]);

    assert!(Retention::Count(5).droppable(10 * DAY, &held()).is_empty());
    assert!(Retention::Count(9).droppable(10 * DAY, &held()).is_empty());
    assert_eq!(Retention::Count(0).droppable(10 * DAY, &held()).len(), 5);
}

// "keep at least the messages of the last d days", counted from when this
// device received them.
#[test]
fn an_age_keeps_what_arrived_inside_the_window() {
    // Now is day 6; a two-day window keeps what arrived on days 4 and 5.
    let dropped = Retention::Age { days: 2 }.droppable(6 * DAY, &held());
    assert_eq!(dropped, vec![id(1), id(2), id(3)]);
}

// The boundary belongs to the keeping side: "at least the messages of the
// last d days" includes one that arrived exactly d days ago.
#[test]
fn a_message_exactly_at_the_boundary_is_kept() {
    let held = [(id(1), 4 * DAY)];
    assert!(
        Retention::Age { days: 2 }
            .droppable(6 * DAY, &held)
            .is_empty()
    );
    assert_eq!(
        Retention::Age { days: 2 }.droppable(6 * DAY + 1, &held),
        vec![id(1)]
    );
}

// The order the caller hands them in is not assumed to be the order they
// arrived in, because a store is not a queue.
#[test]
fn the_order_given_does_not_change_what_is_kept() {
    let mut shuffled = held();
    shuffled.reverse();
    let dropped = Retention::Count(2).droppable(10 * DAY, &shuffled);
    assert_eq!(dropped.len(), 3);
    for kept in [id(4), id(5)] {
        assert!(!dropped.contains(&kept), "{kept:?} is among the newest two");
    }
}

// A clock that went backwards must not delete a group: a receipt time in the
// future is not a reason to drop everything else.
#[test]
fn a_receipt_time_after_now_is_not_a_reason_to_drop_anything_else() {
    let held = [(id(1), 6 * DAY), (id(2), 100 * DAY)];
    let dropped = Retention::Age { days: 2 }.droppable(6 * DAY, &held);
    assert!(
        dropped.is_empty(),
        "both are inside the window or ahead of it"
    );
}
