//! What a relay holds: queues of opaque blobs, with the limits of §5.
//!
//! No files and no clock. The daemon passes the time in and decides where the
//! bytes live; this decides what is allowed.
//!
//! Spec: `spec/60-relay.md` §4a, §5.

use std::collections::BTreeMap;

use onestein_crypto::{HASH_LEN, hash};

use crate::{MAX_BLOB_LEN, MAX_QUEUE_LEN, QUEUE_ID_LEN, Registration};

const BLOB_LABEL: &[u8] = b"org.onestein.relay/BLOB";

/// Relay layer version, in every record and in a blob's name.
pub const RELAY_VERSION: u8 = 1;

/// Milliseconds in a day.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Why a relay said no. Numbers, not sentences: replies that differ by
/// version and locale are one more thing for a censor to match on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No such queue here.
    UnknownQueue = 0,
    /// The proof did not verify.
    BadProof = 1,
    /// The blob is over [`MAX_BLOB_LEN`].
    TooLarge = 2,
    /// The queue is at [`MAX_QUEUE_LEN`].
    QueueFull = 3,
    /// No challenge outstanding for this queue and right.
    UnknownChallenge = 4,
}

/// The name of a blob, derived from the blob.
///
/// A relay cannot hand out a name for a blob it does not hold.
#[must_use]
pub fn blob_id(blob: &[u8]) -> [u8; HASH_LEN] {
    hash(&[BLOB_LABEL, &[RELAY_VERSION], blob])
}

struct Queue {
    registration: Registration,
    blobs: Vec<([u8; HASH_LEN], Vec<u8>, u64)>,
    last_write_ms: u64,
}

/// Every queue this relay holds.
#[derive(Default)]
pub struct Store {
    queues: BTreeMap<[u8; QUEUE_ID_LEN], Queue>,
}

impl Store {
    /// An empty relay.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queues: BTreeMap::new(),
        }
    }

    /// Takes a queue's public keys on first use.
    ///
    /// Registering an existing queue again changes nothing: the keys are
    /// derived from a root key the relay never sees, so a second registration
    /// either matches or comes from someone who cannot write to it anyway.
    pub fn register(
        &mut self,
        queue_id: [u8; QUEUE_ID_LEN],
        registration: Registration,
        now_ms: u64,
    ) {
        self.queues.entry(queue_id).or_insert_with(|| Queue {
            registration,
            blobs: Vec::new(),
            last_write_ms: now_ms,
        });
    }

    /// The keys a queue was registered with.
    #[must_use]
    pub fn registration(&self, queue_id: &[u8; QUEUE_ID_LEN]) -> Option<Registration> {
        self.queues.get(queue_id).map(|queue| queue.registration)
    }

    /// Puts a blob in.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownQueue`], [`Refusal::TooLarge`],
    /// [`Refusal::QueueFull`].
    pub fn write(
        &mut self,
        queue_id: &[u8; QUEUE_ID_LEN],
        blob: Vec<u8>,
        now_ms: u64,
    ) -> Result<[u8; HASH_LEN], Refusal> {
        if blob.len() > MAX_BLOB_LEN {
            return Err(Refusal::TooLarge);
        }
        let queue = self.queues.get_mut(queue_id).ok_or(Refusal::UnknownQueue)?;
        let held: usize = queue.blobs.iter().map(|(_, bytes, _)| bytes.len()).sum();
        if held.saturating_add(blob.len()) > MAX_QUEUE_LEN {
            return Err(Refusal::QueueFull);
        }
        let id = blob_id(&blob);
        queue.blobs.push((id, blob, now_ms));
        queue.last_write_ms = now_ms;
        Ok(id)
    }

    /// The oldest blob, without removing it.
    ///
    /// Reading does not delete. A relay that deleted on read would lose a
    /// message whose reader crashed while receiving it.
    #[must_use]
    pub fn read(&self, queue_id: &[u8; QUEUE_ID_LEN]) -> Option<([u8; HASH_LEN], &[u8])> {
        let queue = self.queues.get(queue_id)?;
        queue
            .blobs
            .first()
            .map(|(id, bytes, _)| (*id, bytes.as_slice()))
    }

    /// Removes a blob by name.
    ///
    /// # Errors
    ///
    /// [`Refusal::UnknownQueue`].
    pub fn delete(
        &mut self,
        queue_id: &[u8; QUEUE_ID_LEN],
        blob_id: &[u8; HASH_LEN],
    ) -> Result<(), Refusal> {
        let queue = self.queues.get_mut(queue_id).ok_or(Refusal::UnknownQueue)?;
        queue.blobs.retain(|(id, _, _)| id != blob_id);
        Ok(())
    }

    /// Drops what has outlived the limits in §5.
    ///
    /// A blob past its expiry goes whether it was collected or not: a relay
    /// that kept it to be helpful would keep a record of a conversation
    /// nobody can read and everybody can subpoena.
    pub fn expire(&mut self, now_ms: u64) {
        let blob_life = crate::BLOB_EXPIRY_DAYS.saturating_mul(DAY_MS);
        let queue_life = crate::QUEUE_EXPIRY_DAYS.saturating_mul(DAY_MS);
        for queue in self.queues.values_mut() {
            queue
                .blobs
                .retain(|(_, _, written)| written.saturating_add(blob_life) >= now_ms);
        }
        self.queues
            .retain(|_, queue| queue.last_write_ms.saturating_add(queue_life) >= now_ms);
    }

    /// How many queues are held, for an operator who wants to know what the
    /// machine is carrying.
    #[must_use]
    pub fn queue_count(&self) -> usize {
        self.queues.len()
    }
}
