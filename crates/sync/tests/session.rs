//! One opportunity to send.
//!
//! Spec: `spec/50-sync.md` §9.

use ed25519_dalek::{Signer, SigningKey};
use onestein_identity::IdentityId;
use onestein_sync::{
    GroupId, Message, Mode, PeerMessageState, Shared, SignedMessage, SyncRecord, plan,
};

const MINUTE: u64 = 60_000;
const BODY: &[u8] = b"hello";

fn signed(body: &'static [u8]) -> SignedMessage<'static> {
    let device = SigningKey::from_bytes(&[0x77; 32]);
    let message = Message {
        group_id: GroupId::derive("com.example.test", 1, &[0x01]).expect("derives"),
        timestamp_ms: 1_600_000_000_000,
        author: IdentityId::derive(&[0x11; 32], &[0x22; 1952]).expect("derives"),
        device_key: device.verifying_key().to_bytes(),
        body,
    };
    let to_sign = message.to_sign().expect("signs");
    SignedMessage {
        message,
        signature: device.sign(&to_sign).to_bytes(),
    }
}

fn shared(state: PeerMessageState) -> Shared<'static> {
    let message = signed(BODY);
    Shared {
        id: message.message.id().expect("derives"),
        state,
        message: Some(message),
    }
}

// Interactive mode offers what the peer has not seen, and does not send it
// until it is asked for.
#[test]
fn interactive_offers_before_it_sends() {
    let mut store = [shared(PeerMessageState::new())];
    let records = plan(Mode::Interactive, 0, MINUTE, &mut store, &[]);
    assert!(matches!(records.as_slice(), [SyncRecord::Offer(ids)] if ids.len() == 1));

    let mut requested = PeerMessageState::new();
    requested.on_peer_requested();
    let mut store = [shared(requested)];
    let records = plan(Mode::Interactive, 0, MINUTE, &mut store, &[]);
    assert!(matches!(records.as_slice(), [SyncRecord::Message(_)]));
}

#[test]
fn batch_sends_without_offering() {
    let mut store = [shared(PeerMessageState::new())];
    let records = plan(Mode::Batch, 0, MINUTE, &mut store, &[]);
    assert!(matches!(records.as_slice(), [SyncRecord::Message(_)]));
}

// "Respects next_send_time: yes, yes, no." Eager mode is that row.
#[test]
fn only_eager_mode_sends_before_the_backoff_is_over() {
    let mut state = PeerMessageState::new();
    state.on_sent(0, MINUTE);
    let waiting = state;

    let mut store = [shared(waiting)];
    assert!(plan(Mode::Batch, 1, MINUTE, &mut store, &[]).is_empty());

    let mut store = [shared(waiting)];
    assert!(plan(Mode::Interactive, 1, MINUTE, &mut store, &[]).is_empty());

    let mut store = [shared(waiting)];
    assert!(matches!(
        plan(Mode::Eager, 1, MINUTE, &mut store, &[]).as_slice(),
        [SyncRecord::Message(_)]
    ));
}

#[test]
fn what_the_peer_has_seen_is_neither_offered_nor_sent() {
    let mut seen = PeerMessageState::new();
    seen.on_peer_acked();
    for mode in [Mode::Interactive, Mode::Batch, Mode::Eager] {
        let mut store = [shared(seen)];
        assert!(
            plan(mode, 0, MINUTE, &mut store, &[]).is_empty(),
            "{mode:?}"
        );
    }
}

// An acknowledgement is owed in every mode, and sending it clears the flag.
#[test]
fn an_owed_acknowledgement_goes_out_once() {
    let mut owed = PeerMessageState::new();
    owed.on_peer_offered();
    let mut store = [shared(owed)];

    let records = plan(Mode::Interactive, 0, MINUTE, &mut store, &[]);
    assert!(
        records
            .iter()
            .any(|record| matches!(record, SyncRecord::Ack(_)))
    );
    assert!(!store[0].state.ack_pending);

    let records = plan(Mode::Interactive, 0, MINUTE, &mut store, &[]);
    assert!(
        !records
            .iter()
            .any(|record| matches!(record, SyncRecord::Ack(_)))
    );
}

// "A message the device no longer holds is answered with UNAVAILABLE and not
// with silence, whichever mode it is in."
#[test]
fn a_request_for_something_gone_is_answered() {
    let mut requested = PeerMessageState::new();
    requested.on_peer_requested();
    let mut store = [Shared {
        id: signed(BODY).message.id().expect("derives"),
        state: requested,
        message: None,
    }];

    let records = plan(Mode::Batch, 0, MINUTE, &mut store, &[]);
    assert!(matches!(records.as_slice(), [SyncRecord::Unavailable(ids)] if ids.len() == 1));
}

#[test]
fn identifiers_the_peer_offered_are_requested() {
    let wanted = signed(b"elsewhere").message.id().expect("derives");
    let mut store: [Shared<'_>; 0] = [];
    let records = plan(Mode::Interactive, 0, MINUTE, &mut store, &[wanted]);
    assert_eq!(records, vec![SyncRecord::Request(vec![wanted])]);
}

// "A device never sends an empty record."
#[test]
fn nothing_to_say_means_nothing_is_sent() {
    let mut store: [Shared<'_>; 0] = [];
    for mode in [Mode::Interactive, Mode::Batch, Mode::Eager] {
        assert!(
            plan(mode, 0, MINUTE, &mut store, &[]).is_empty(),
            "{mode:?}"
        );
    }
}

// Sending moves the state, or the next opportunity would send the same thing
// again and the backoff would never start.
#[test]
fn sending_advances_the_state_it_acted_on() {
    let mut store = [shared(PeerMessageState::new())];
    let records = plan(Mode::Batch, 1_000, MINUTE, &mut store, &[]);
    assert!(matches!(records.as_slice(), [SyncRecord::Message(_)]));

    assert_eq!(store[0].state.send_count, 1);
    assert!(store[0].state.next_send_time > 1_000);
    assert_eq!(store[0].state.max_latency, MINUTE);
}
