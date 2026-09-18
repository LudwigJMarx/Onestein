//! A relay daemon.
//!
//! The first program in this repository that opens a socket. The library it
//! serves does not, which is the point: everything that decides lives in
//! `onestein-relay` and is tested without a network, and what is here is the
//! part that cannot be.
//!
//! It knows nothing about its users. There are no accounts, so there is no
//! user list to lose, and no way to tell abuse from use
//! (`spec/60-relay.md` §9).

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use onestein_relay::{Challenges, Response, Store, decode_request, encode_response, handle};

/// Bytes of record header before a payload.
const HEADER_LEN: usize = 4;

/// The most a single record may carry, matching the framing.
const MAX_RECORD_LEN: usize = 48 * 1024;

/// Everything the daemon holds, which is queues and outstanding challenges.
#[derive(Default)]
pub struct Shared {
    store: Store,
    challenges: Challenges,
}

impl Shared {
    /// An empty relay.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Store::new(),
            challenges: Challenges::new(),
        }
    }

    /// How many queues are held.
    #[must_use]
    pub fn queue_count(&self) -> usize {
        self.store.queue_count()
    }
}

/// Serves until the listener fails.
///
/// One thread per connection, which is what a relay's traffic looks like:
/// long idles and short exchanges. A connection that misbehaves is dropped
/// and costs nothing else.
pub fn serve(listener: &TcpListener, shared: &Arc<Mutex<Shared>>) {
    for connection in listener.incoming() {
        let Ok(stream) = connection else {
            continue;
        };
        let shared = Arc::clone(shared);
        std::thread::spawn(move || {
            // A failed connection is not an event worth a line: a relay that
            // logged every dropped socket would keep a record of who called.
            drop(converse(stream, &shared));
        });
    }
}

/// Answers one connection until it closes.
///
/// # Errors
///
/// Any failure of the socket, which ends the conversation and nothing else.
pub fn converse(mut stream: TcpStream, shared: &Arc<Mutex<Shared>>) -> std::io::Result<()> {
    loop {
        let mut header = [0u8; HEADER_LEN];
        if stream.read_exact(&mut header).is_err() {
            return Ok(());
        }
        let length = usize::from(u16::from_be_bytes([
            header.get(2).copied().unwrap_or(0),
            header.get(3).copied().unwrap_or(0),
        ]));
        if length > MAX_RECORD_LEN {
            return Ok(());
        }

        let mut record = Vec::with_capacity(HEADER_LEN.saturating_add(length));
        record.extend_from_slice(&header);
        record.resize(HEADER_LEN.saturating_add(length), 0);
        if let Some(payload) = record.get_mut(HEADER_LEN..) {
            stream.read_exact(payload)?;
        }

        let reply = answer(&record, shared);
        stream.write_all(&reply)?;
        stream.flush()?;
    }
}

/// Turns one record into one reply, holding the lock for as short a time as
/// it takes to decide.
fn answer(record: &[u8], shared: &Arc<Mutex<Shared>>) -> Vec<u8> {
    let now_ms = now_ms();
    let mut challenge = [0u8; 32];
    // A challenge nobody can predict is the whole of the replay defence, so a
    // generator that failed would have to stop the answer, not weaken it.
    if getrandom::fill(&mut challenge).is_err() {
        return encode_response(&Response::Empty).unwrap_or_default();
    }

    let Ok(mut held) = shared.lock() else {
        return encode_response(&Response::Empty).unwrap_or_default();
    };
    let Shared { store, challenges } = &mut *held;
    store.expire(now_ms);

    let Ok(request) = decode_request(record) else {
        return encode_response(&Response::Empty).unwrap_or_default();
    };
    let response = handle(store, challenges, &request, now_ms, challenge);
    encode_response(&response).unwrap_or_default()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
