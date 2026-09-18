//! What a device remembers about one message and one peer.
//!
//! Six fields per message per peer, and the caller stores them: this crate
//! takes the numbers in and hands them back, like every other layer here.
//!
//! Spec: `spec/50-sync.md` §8.

/// What a device knows about one message in relation to one peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerMessageState {
    /// The peer is known to hold the message.
    pub seen: bool,
    /// The peer has offered or sent it since we last acknowledged, so an
    /// acknowledgement is owed.
    ///
    /// Named for what it means. The flag that says "we have acknowledged"
    /// would be its inverse, and an implementer who confused the two would
    /// acknowledge nothing, which looks from the other side like a peer that
    /// keeps resending.
    pub ack_pending: bool,
    /// The peer has asked for it since we last offered or sent it.
    pub requested: bool,
    /// How often it has been offered or sent to this peer.
    pub send_count: u32,
    /// The earliest time it may be offered or sent again, in milliseconds
    /// since the Unix epoch. Zero means now.
    pub next_send_time: u64,
    /// The latency of the transport last used for it, in milliseconds.
    pub max_latency: u64,
}

/// The most the backoff doubles before it stops growing.
///
/// The specification fixes that the delay grows with the send count and
/// leaves the rate open, so this is ours. Ten doublings of a one-minute
/// transport is about seventeen hours, which is longer than any transport in
/// `20-transport.md` waits and short enough that a message is still retried
/// after a weekend.
pub const MAX_BACKOFF_DOUBLINGS: u32 = 10;

impl PeerMessageState {
    /// A message that has never been offered or sent to this peer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seen: false,
            ack_pending: false,
            requested: false,
            send_count: 0,
            next_send_time: 0,
            max_latency: 0,
        }
    }

    /// Whether the message may be offered or sent now.
    #[must_use]
    pub const fn ready_to_send(&self, now_ms: u64) -> bool {
        now_ms >= self.next_send_time
    }

    /// Records that the message was offered or sent over a transport of this
    /// latency.
    ///
    /// Offering and sending are one event here because the specification
    /// counts them as one: both tell the peer the message exists, and both
    /// start the wait for an answer.
    pub fn on_sent(&mut self, now_ms: u64, transport_latency_ms: u64) {
        self.send_count = self.send_count.saturating_add(1);
        self.max_latency = transport_latency_ms;
        self.requested = false;

        // The delay doubles with each attempt and then stops. A backoff that
        // doubles forever overflows, and an overflowed send time is a message
        // that is never retried at all.
        let doublings = self.send_count.saturating_sub(1).min(MAX_BACKOFF_DOUBLINGS);
        let factor = 1u64 << doublings;
        let delay = transport_latency_ms.saturating_mul(factor).max(1);
        self.next_send_time = now_ms.saturating_add(delay);
    }

    /// The peer acknowledged the message, so it holds it.
    pub const fn on_peer_acked(&mut self) {
        self.seen = true;
    }

    /// The peer offered or sent the message: it holds it, and we owe an
    /// acknowledgement.
    pub const fn on_peer_offered(&mut self) {
        self.seen = true;
        self.ack_pending = true;
    }

    /// We acknowledged the message to the peer.
    pub const fn on_acknowledged(&mut self) {
        self.ack_pending = false;
    }

    /// The peer asked for the message.
    pub const fn on_peer_requested(&mut self) {
        self.requested = true;
    }
}
