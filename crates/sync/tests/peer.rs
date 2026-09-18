//! Per-peer, per-message state.
//!
//! Spec: `spec/50-sync.md` §8.

use onestein_sync::{MAX_BACKOFF_DOUBLINGS, PeerMessageState};

const MINUTE: u64 = 60_000;

#[test]
fn a_fresh_state_may_be_sent_at_once_and_knows_nothing() {
    let state = PeerMessageState::new();
    assert!(!state.seen);
    assert!(!state.ack_pending);
    assert!(!state.requested);
    assert_eq!(state.send_count, 0);
    assert!(state.ready_to_send(0));
}

#[test]
fn sending_counts_and_holds_the_message_back_until_its_time() {
    let mut state = PeerMessageState::new();
    state.on_sent(1_000, MINUTE);

    assert_eq!(state.send_count, 1);
    assert_eq!(state.max_latency, MINUTE);
    assert!(state.next_send_time > 1_000);
    assert!(!state.ready_to_send(state.next_send_time - 1));
    assert!(state.ready_to_send(state.next_send_time));
}

// "BSP only requires that the send time should increase exponentially with
// the send count." The rate is ours; that it grows is not.
#[test]
fn every_further_attempt_waits_longer_than_the_last() {
    let mut state = PeerMessageState::new();
    let mut previous = 0;
    let mut now = 0;
    for _ in 0..6 {
        state.on_sent(now, MINUTE);
        let delay = state.next_send_time.saturating_sub(now);
        assert!(delay > previous, "delay {delay} must exceed {previous}");
        previous = delay;
        now = state.next_send_time;
    }
}

// A backoff that doubles forever overflows, and an overflowed send time is a
// message that is never retried again.
#[test]
fn the_backoff_stops_growing_instead_of_overflowing() {
    let mut state = PeerMessageState::new();
    let mut now = 0;
    let mut last_delay = 0;
    for _ in 0..(MAX_BACKOFF_DOUBLINGS + 20) {
        state.on_sent(now, MINUTE);
        last_delay = state.next_send_time.saturating_sub(now);
        now = state.next_send_time;
    }
    // Capped, not overflowed: still waiting, and waiting a knowable amount.
    assert_eq!(last_delay, MINUTE << MAX_BACKOFF_DOUBLINGS);
    assert!(state.next_send_time < u64::MAX);

    let mut late = PeerMessageState::new();
    late.on_sent(u64::MAX - 1, MINUTE);
    assert_eq!(late.next_send_time, u64::MAX);
}

#[test]
fn an_acknowledgement_from_the_peer_means_it_holds_the_message() {
    let mut state = PeerMessageState::new();
    state.on_peer_acked();
    assert!(state.seen);
    assert!(!state.ack_pending);
}

// An offer says two things at once: the peer has it, and we owe an
// acknowledgement for having been told.
#[test]
fn an_offer_from_the_peer_leaves_an_acknowledgement_owed() {
    let mut state = PeerMessageState::new();
    state.on_peer_offered();
    assert!(state.seen);
    assert!(state.ack_pending);

    state.on_acknowledged();
    assert!(!state.ack_pending);
    assert!(
        state.seen,
        "acknowledging does not unlearn that the peer has it"
    );
}

// "Request flag - raised if the peer has requested the message since the
// device last offered or sent it."
#[test]
fn a_request_is_cleared_by_sending_and_not_before() {
    let mut state = PeerMessageState::new();
    state.on_peer_requested();
    assert!(state.requested);

    state.on_peer_acked();
    assert!(state.requested, "an acknowledgement is not a delivery");

    state.on_sent(1_000, MINUTE);
    assert!(!state.requested);
}

// The whole point of the record: it survives a restart because the caller
// stores it, and it is six plain numbers.
#[test]
fn the_state_is_copyable_and_comparable() {
    let mut state = PeerMessageState::new();
    state.on_peer_offered();
    state.on_sent(500, MINUTE);
    let stored = state;
    assert_eq!(stored, state);
}
