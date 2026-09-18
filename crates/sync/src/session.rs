//! One opportunity to send: what goes out, and what the state becomes.
//!
//! No sockets, no clock, no storage. The caller says what it holds, what the
//! peer has asked for and what time it is; this decides what to send and
//! updates the per-peer state it acted on. Where the bytes then go is the
//! application's business, and so is whether the connection survives.
//!
//! Spec: `spec/50-sync.md` §9.

use crate::{MessageId, PeerMessageState, SignedMessage, SyncRecord};

/// How a device spends one opportunity to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Offer first, send what is requested. Fewest bytes, two round trips.
    Interactive,
    /// Send without offering. One round trip, more bytes.
    Batch,
    /// Send without offering and without waiting for the backoff. Most bytes,
    /// for transports that lose things.
    Eager,
}

/// One message this device shares with the peer.
pub struct Shared<'a> {
    /// Its identifier.
    pub id: MessageId,
    /// What this device knows about it in relation to this peer. Updated in
    /// place for whatever is sent.
    pub state: PeerMessageState,
    /// The message itself, or `None` when this device no longer holds it.
    ///
    /// A message can be shared and gone: the graph keeps its position after
    /// the body is deleted (§1), and a request for it is answered with
    /// UNAVAILABLE rather than silence.
    pub message: Option<SignedMessage<'a>>,
}

/// Decides what to send now.
///
/// `offered_by_peer` are identifiers the peer has offered that this device
/// does not hold and has not yet requested. The caller keeps that list,
/// because it is about messages this device knows nothing else about.
#[must_use]
pub fn plan<'a>(
    mode: Mode,
    now_ms: u64,
    transport_latency_ms: u64,
    shared: &mut [Shared<'a>],
    offered_by_peer: &[MessageId],
) -> Vec<SyncRecord<'a>> {
    let mut acks = Vec::new();
    let mut unavailable = Vec::new();
    let mut offers = Vec::new();
    let mut messages = Vec::new();

    for entry in shared.iter_mut() {
        if entry.state.ack_pending {
            acks.push(entry.id);
            entry.state.on_acknowledged();
        }

        // Eager mode is this line: it ignores the backoff and resends.
        let ready = matches!(mode, Mode::Eager) || entry.state.ready_to_send(now_ms);
        if !ready {
            continue;
        }

        let wanted = entry.state.requested;
        let send = match mode {
            Mode::Interactive => wanted,
            Mode::Batch | Mode::Eager => wanted || !entry.state.seen,
        };

        if send {
            match entry.message {
                Some(message) => messages.push(SyncRecord::Message(message)),
                // Shared and gone: the graph keeps the position, the body is
                // deleted, and the answer is a record rather than silence.
                None => unavailable.push(entry.id),
            }
            entry.state.on_sent(now_ms, transport_latency_ms);
        } else if matches!(mode, Mode::Interactive) && !entry.state.seen {
            offers.push(entry.id);
            entry.state.on_sent(now_ms, transport_latency_ms);
        }
    }

    // Nothing empty goes out: every identifier record says "one or more", and
    // an empty one costs a round trip to say nothing.
    let mut records = Vec::new();
    if !acks.is_empty() {
        records.push(SyncRecord::Ack(acks));
    }
    if !offered_by_peer.is_empty() {
        records.push(SyncRecord::Request(offered_by_peer.to_vec()));
    }
    if !unavailable.is_empty() {
        records.push(SyncRecord::Unavailable(unavailable));
    }
    records.extend(messages);
    if !offers.is_empty() {
        records.push(SyncRecord::Offer(offers));
    }
    records
}
